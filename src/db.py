"""
db.py — PostgreSQL database module

Manages the database schema, connection pooling, and all
CRUD operations for storing normalised threat indicators.

Schema design:
  - threat_indicators: main table storing all normalised IOCs
  - correlation_results: stores ML correlation scores per indicator
  - ingestion_log: tracks API fetch runs for audit and monitoring

Deduplication: each indicator is identified by its dedup_key
(SHA-256 of indicator_value + source_feed). On conflict, we
update the existing record with the latest data rather than
inserting a duplicate.
"""

import logging
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional, Generator

import psycopg2
import psycopg2.extras
from psycopg2.pool import ThreadedConnectionPool

from config import Config
from normaliser import ThreatIndicator

logger = logging.getLogger(__name__)


# ── SQL Definitions ───────────────────────────────────────────────────────────

CREATE_THREAT_INDICATORS = """
CREATE TABLE IF NOT EXISTS threat_indicators (
    id                SERIAL PRIMARY KEY,
    dedup_key         VARCHAR(64)  NOT NULL UNIQUE,
    indicator_value   TEXT         NOT NULL,
    indicator_type    VARCHAR(20)  NOT NULL,
    source_feed       VARCHAR(30)  NOT NULL,
    threat_category   VARCHAR(20)  NOT NULL,
    confidence_score  FLOAT        NOT NULL DEFAULT 0.0,
    severity_score    FLOAT        NOT NULL DEFAULT 0.0,
    malicious_count   INTEGER      NOT NULL DEFAULT 0,
    total_count       INTEGER      NOT NULL DEFAULT 0,
    country_code      VARCHAR(5),
    asn               VARCHAR(20),
    isp               TEXT,
    tags              TEXT[],
    description       TEXT,
    first_seen        TIMESTAMPTZ,
    last_seen         TIMESTAMPTZ,
    fetched_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    created_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ  NOT NULL DEFAULT NOW()
);
"""

CREATE_CORRELATION_RESULTS = """
CREATE TABLE IF NOT EXISTS correlation_results (
    id                  SERIAL PRIMARY KEY,
    indicator_value     TEXT        NOT NULL,
    indicator_type      VARCHAR(20) NOT NULL,
    otx_score           FLOAT,
    vt_score            FLOAT,
    abuseipdb_score     FLOAT,
    combined_score      FLOAT       NOT NULL DEFAULT 0.0,
    predicted_category  VARCHAR(20),
    ml_confidence       FLOAT,
    is_malicious        BOOLEAN     NOT NULL DEFAULT FALSE,
    sources_agreed      INTEGER     NOT NULL DEFAULT 0,
    correlated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""

CREATE_INGESTION_LOG = """
CREATE TABLE IF NOT EXISTS ingestion_log (
    id              SERIAL PRIMARY KEY,
    source_feed     VARCHAR(30) NOT NULL,
    indicator_type  VARCHAR(20),
    indicators_fetched  INTEGER NOT NULL DEFAULT 0,
    indicators_stored   INTEGER NOT NULL DEFAULT 0,
    duplicates_skipped  INTEGER NOT NULL DEFAULT 0,
    errors_encountered  INTEGER NOT NULL DEFAULT 0,
    duration_seconds    FLOAT,
    run_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"""

CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_indicator_value ON threat_indicators(indicator_value);",
    "CREATE INDEX IF NOT EXISTS idx_indicator_type  ON threat_indicators(indicator_type);",
    "CREATE INDEX IF NOT EXISTS idx_source_feed     ON threat_indicators(source_feed);",
    "CREATE INDEX IF NOT EXISTS idx_threat_category ON threat_indicators(threat_category);",
    "CREATE INDEX IF NOT EXISTS idx_confidence      ON threat_indicators(confidence_score DESC);",
    "CREATE INDEX IF NOT EXISTS idx_fetched_at      ON threat_indicators(fetched_at DESC);",
    "CREATE INDEX IF NOT EXISTS idx_corr_value      ON correlation_results(indicator_value);",
]

UPSERT_INDICATOR = """
INSERT INTO threat_indicators (
    dedup_key, indicator_value, indicator_type, source_feed,
    threat_category, confidence_score, severity_score,
    malicious_count, total_count, country_code, asn, isp,
    tags, description, first_seen, last_seen, fetched_at
) VALUES (
    %(dedup_key)s, %(indicator_value)s, %(indicator_type)s, %(source_feed)s,
    %(threat_category)s, %(confidence_score)s, %(severity_score)s,
    %(malicious_count)s, %(total_count)s, %(country_code)s, %(asn)s, %(isp)s,
    %(tags)s, %(description)s, %(first_seen)s, %(last_seen)s, %(fetched_at)s
)
ON CONFLICT (dedup_key) DO UPDATE SET
    confidence_score = EXCLUDED.confidence_score,
    severity_score   = EXCLUDED.severity_score,
    malicious_count  = EXCLUDED.malicious_count,
    total_count      = EXCLUDED.total_count,
    threat_category  = EXCLUDED.threat_category,
    tags             = EXCLUDED.tags,
    description      = EXCLUDED.description,
    last_seen        = EXCLUDED.last_seen,
    fetched_at       = EXCLUDED.fetched_at,
    updated_at       = NOW()
RETURNING id, (xmax = 0) AS inserted;
"""


# ── Database Manager ──────────────────────────────────────────────────────────

class DatabaseManager:
    """
    Manages PostgreSQL connections and all database operations.

    Uses a ThreadedConnectionPool for efficient connection reuse
    in concurrent ingestion scenarios.
    """

    def __init__(self) -> None:
        self._pool: Optional[ThreadedConnectionPool] = None

    def connect(self, min_conn: int = 1, max_conn: int = 5) -> None:
        """
        Initialise the connection pool and create the schema if needed.
        Call this once at application startup.
        """
        logger.info(f"Connecting to PostgreSQL: {Config.DB_HOST}:{Config.DB_PORT}/{Config.DB_NAME}")
        self._pool = ThreadedConnectionPool(
            minconn=min_conn,
            maxconn=max_conn,
            host=Config.DB_HOST,
            port=Config.DB_PORT,
            dbname=Config.DB_NAME,
            user=Config.DB_USER,
            password=Config.DB_PASSWORD,
        )
        self._init_schema()
        logger.info("Database connection pool established.")

    def _init_schema(self) -> None:
        """Create all tables and indexes if they do not yet exist."""
        with self.cursor() as cur:
            cur.execute(CREATE_THREAT_INDICATORS)
            cur.execute(CREATE_CORRELATION_RESULTS)
            cur.execute(CREATE_INGESTION_LOG)
            for idx_sql in CREATE_INDEXES:
                cur.execute(idx_sql)
        logger.info("Database schema initialised (tables and indexes verified).")

    @contextmanager
    def cursor(self) -> Generator:
        """
        Context manager providing a database cursor.
        Automatically commits on success, rolls back on exception.
        """
        if self._pool is None:
            raise RuntimeError("DatabaseManager.connect() must be called before use.")
        conn = self._pool.getconn()
        try:
            with conn:
                with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                    yield cur
        finally:
            self._pool.putconn(conn)

    def close(self) -> None:
        """Close all connections in the pool."""
        if self._pool:
            self._pool.closeall()
            logger.info("Database connection pool closed.")

    # ── CRUD Operations ───────────────────────────────────────────────────────

    def store_indicator(self, indicator: ThreatIndicator) -> tuple[int, bool]:
        """
        Insert or update a ThreatIndicator in the database.

        Returns:
            (id, inserted): id of the row, True if newly inserted
        """
        data = indicator.to_dict()
        # psycopg2 needs Python list for TEXT[] array column
        data["tags"] = data.get("tags", []) or []

        with self.cursor() as cur:
            cur.execute(UPSERT_INDICATOR, data)
            row = cur.fetchone()
            return row["id"], row["inserted"]

    def store_indicators_batch(
        self, indicators: list[ThreatIndicator]
    ) -> tuple[int, int]:
        """
        Store a batch of indicators.

        Returns:
            (inserted_count, updated_count)
        """
        inserted = updated = 0
        for indicator in indicators:
            _, is_new = self.store_indicator(indicator)
            if is_new:
                inserted += 1
            else:
                updated += 1
        logger.info(
            f"DB | Batch stored: {inserted} new, {updated} updated "
            f"({len(indicators)} total)"
        )
        return inserted, updated

    def get_indicator(
        self, indicator_value: str, source_feed: Optional[str] = None
    ) -> list[dict]:
        """
        Retrieve indicators by value, optionally filtered by source feed.
        Returns all matching records as list of dicts.
        """
        with self.cursor() as cur:
            if source_feed:
                cur.execute(
                    "SELECT * FROM threat_indicators "
                    "WHERE indicator_value = %s AND source_feed = %s "
                    "ORDER BY fetched_at DESC",
                    (indicator_value, source_feed)
                )
            else:
                cur.execute(
                    "SELECT * FROM threat_indicators "
                    "WHERE indicator_value = %s "
                    "ORDER BY fetched_at DESC",
                    (indicator_value,)
                )
            return cur.fetchall()

    def get_high_confidence_indicators(
        self, min_confidence: float = 0.7, limit: int = 100
    ) -> list[dict]:
        """
        Retrieve high-confidence threat indicators for ML training
        or dashboard display.
        """
        with self.cursor() as cur:
            cur.execute(
                "SELECT * FROM threat_indicators "
                "WHERE confidence_score >= %s "
                "ORDER BY confidence_score DESC, fetched_at DESC "
                "LIMIT %s",
                (min_confidence, limit)
            )
            return cur.fetchall()

    def get_stats(self) -> dict:
        """
        Return summary statistics for the Grafana dashboard.
        """
        with self.cursor() as cur:
            cur.execute("""
                SELECT
                    COUNT(*)                            AS total_indicators,
                    COUNT(DISTINCT indicator_value)     AS unique_indicators,
                    COUNT(DISTINCT source_feed)         AS active_feeds,
                    AVG(confidence_score)               AS avg_confidence,
                    MAX(fetched_at)                     AS last_ingestion,
                    COUNT(*) FILTER (WHERE confidence_score >= 0.7) AS high_confidence_count
                FROM threat_indicators
            """)
            return dict(cur.fetchone())

    def log_ingestion_run(
        self,
        source_feed: str,
        indicator_type: Optional[str],
        fetched: int,
        stored: int,
        duplicates: int,
        errors: int,
        duration: float,
    ) -> None:
        """Record an ingestion run in the audit log."""
        with self.cursor() as cur:
            cur.execute(
                """
                INSERT INTO ingestion_log (
                    source_feed, indicator_type, indicators_fetched,
                    indicators_stored, duplicates_skipped, errors_encountered,
                    duration_seconds
                ) VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                (source_feed, indicator_type, fetched, stored, duplicates, errors, duration)
            )


# ── Module-level singleton ────────────────────────────────────────────────────
db = DatabaseManager()
