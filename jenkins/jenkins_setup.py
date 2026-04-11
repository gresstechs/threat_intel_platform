"""
jenkins_setup.py — Jenkins CI/CD Setup Verification Script

Run this script to verify your Jenkins environment is correctly
configured to execute the Threat Intelligence Platform pipeline.

Usage:
    python jenkins/jenkins_setup.py

Checks performed:
  1. Python version (3.10+)
  2. Required packages installed
  3. Environment variables / credentials present
  4. Database connectivity
  5. API key validity (basic check)
  6. Jenkins workspace write permissions
"""

import sys
import os
import subprocess

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'src'))

PASS = "✅"
FAIL = "❌"
WARN = "⚠️"

results = []

def check(name, condition, message, warning=False):
    symbol = PASS if condition else (WARN if warning else FAIL)
    status = "PASS" if condition else ("WARN" if warning else "FAIL")
    results.append((symbol, name, status, message))
    print(f"  {symbol}  {name:<40} {message}")
    return condition

print("\n" + "="*70)
print("  THREAT INTEL PLATFORM — JENKINS SETUP VERIFICATION")
print("="*70 + "\n")

# ── 1. Python Version ─────────────────────────────────────────────────────────
print("1. Python Environment")
py_version = sys.version_info
check(
    "Python version >= 3.10",
    py_version >= (3, 10),
    f"Python {py_version.major}.{py_version.minor}.{py_version.micro}"
)

# ── 2. Required Packages ──────────────────────────────────────────────────────
print("\n2. Required Packages")
required_packages = [
    ("requests",      "requests"),
    ("python-dotenv", "dotenv"),
    ("psycopg2",      "psycopg2"),
    ("tenacity",      "tenacity"),
    ("pytest",        "pytest"),
    ("scikit-learn",  "sklearn"),
    ("xgboost",       "xgboost"),
    ("pandas",        "pandas"),
    ("joblib",        "joblib"),
]

for pkg_name, import_name in required_packages:
    try:
        __import__(import_name)
        check(f"Package: {pkg_name}", True, "Installed")
    except ImportError:
        check(f"Package: {pkg_name}", False, f"NOT INSTALLED — run: pip install {pkg_name}")

# ── 3. Environment Variables ──────────────────────────────────────────────────
print("\n3. Environment Variables / Credentials")
try:
    from dotenv import load_dotenv
    load_dotenv()
    from config import Config

    check("OTX_API_KEY",       bool(Config.OTX_API_KEY),       "Present" if Config.OTX_API_KEY else "MISSING")
    check("VT_API_KEY",        bool(Config.VT_API_KEY),        "Present" if Config.VT_API_KEY else "MISSING")
    check("ABUSEIPDB_API_KEY", bool(Config.ABUSEIPDB_API_KEY), "Present" if Config.ABUSEIPDB_API_KEY else "MISSING")
    check("DB_HOST",           bool(Config.DB_HOST),           Config.DB_HOST or "MISSING")
    check("DB_NAME",           bool(Config.DB_NAME),           Config.DB_NAME or "MISSING")
    check("DB_USER",           bool(Config.DB_USER),           Config.DB_USER or "MISSING")
    check("DB_PASSWORD",       bool(Config.DB_PASSWORD),       "Set" if Config.DB_PASSWORD else "MISSING")

except Exception as e:
    check("Config module", False, f"Failed to load: {e}")

# ── 4. Database Connectivity ──────────────────────────────────────────────────
print("\n4. Database Connectivity")
try:
    from db import db
    db.connect(min_conn=1, max_conn=2)
    stats = db.get_stats()
    check(
        "PostgreSQL connection",
        True,
        f"Connected — {stats['total_indicators']} indicators stored"
    )
    db.close()
except Exception as e:
    check("PostgreSQL connection", False, f"FAILED: {e}")

# ── 5. Model Registry ─────────────────────────────────────────────────────────
print("\n5. ML Model Registry")
try:
    from db import db
    db.connect(min_conn=1, max_conn=2)
    with db.cursor() as cur:
        cur.execute("SELECT COUNT(*) as cnt FROM ml_model_registry WHERE is_active = TRUE")
        row = cur.fetchone()
        active_models = row["cnt"] if row else 0
    check(
        "Active model in registry",
        active_models > 0,
        f"{active_models} active model(s) found",
        warning=(active_models == 0)
    )
    db.close()
except Exception as e:
    check("Model registry", False, f"FAILED: {e}", warning=True)

# ── 6. Pipeline Runner ────────────────────────────────────────────────────────
print("\n6. Pipeline Runner")
try:
    import pipeline_runner
    check("pipeline_runner.py", True, "Importable")
except ImportError as e:
    check("pipeline_runner.py", False, f"Import failed: {e}")

try:
    from alert_prioritiser import AlertPrioritiser
    ap = AlertPrioritiser()
    check("AlertPrioritiser", True, "Instantiated successfully")
except Exception as e:
    check("AlertPrioritiser", False, f"Failed: {e}")

# ── 7. Workspace Write Permissions ────────────────────────────────────────────
print("\n7. Workspace Permissions")
try:
    os.makedirs("reports", exist_ok=True)
    test_file = "reports/.jenkins_write_test"
    with open(test_file, "w") as f:
        f.write("test")
    os.remove(test_file)
    check("reports/ directory writable", True, "Write test passed")
except Exception as e:
    check("reports/ directory writable", False, f"Write test failed: {e}")

try:
    os.makedirs("models", exist_ok=True)
    test_file = "models/.jenkins_write_test"
    with open(test_file, "w") as f:
        f.write("test")
    os.remove(test_file)
    check("models/ directory writable", True, "Write test passed")
except Exception as e:
    check("models/ directory writable", False, f"Write test failed: {e}")

# ── Summary ───────────────────────────────────────────────────────────────────
print("\n" + "="*70)
passed  = sum(1 for r in results if r[2] == "PASS")
failed  = sum(1 for r in results if r[2] == "FAIL")
warned  = sum(1 for r in results if r[2] == "WARN")
total   = len(results)

print(f"  RESULTS: {passed}/{total} passed  |  {warned} warnings  |  {failed} failures")

if failed == 0:
    print(f"  {PASS} Jenkins environment is correctly configured")
    print("  Ready to run: python src/pipeline_runner.py --stage ingest")
else:
    print(f"  {FAIL} {failed} issue(s) must be resolved before running the pipeline")

print("="*70 + "\n")

sys.exit(0 if failed == 0 else 1)
