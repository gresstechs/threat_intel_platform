#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# setup_repo.sh — One-time repository initialisation and push to GitHub
# Run this from inside the threat_intel_platform/ folder
# ─────────────────────────────────────────────────────────────────────────────

# Step 1: Initialise git
git init

# Step 2: Set your identity (update with your details)
git config user.name "Chidera Progress Nwaokwa"
git config user.email "bi78xz@student.sunderland.ac.uk"

# Step 3: Create organised folder structure
mkdir -p src/api src/core src/ml src/automation/playbooks
mkdir -p tests dashboards/grafana docs jenkins

# Step 4: Move source files into proper src structure
mv config.py       src/core/
mv normaliser.py   src/core/
mv db.py           src/core/
mv otx_client.py   src/api/
mv virustotal_client.py src/api/
mv abuseipdb_client.py  src/api/
mv main.py         src/
mv tests/test_platform.py tests/

# Step 5: Stage everything
git add .

# Step 6: Initial commit
git commit -m "Initial commit: D1.3 API Integration Module

- AlienVault OTX, VirusTotal, AbuseIPDB clients
- Unified ThreatIndicator normalisation schema
- PostgreSQL database layer with UPSERT deduplication
- CLI orchestrator (main.py)
- 42 unit tests - all passing
- D1.3 technical documentation

Deliverable: D1.3 (Week 6) - Three threat feeds integrated
Ethics Reference: 035333"

# Step 7: Rename default branch to main
git branch -M main

# Step 8: Add GitHub remote (private repo must be created first on GitHub)
git remote add origin https://github.com/gresstechs/threat-intel-platform.git

# Step 9: Push to GitHub
git push -u origin main

echo ""
echo "✅ Repository pushed to: https://github.com/gresstechs/threat-intel-platform"
echo ""
