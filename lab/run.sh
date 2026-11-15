#!/usr/bin/env bash
# Bring the lab up, scan Juice Shop with Nmap, Nuclei, ZAP baseline and Trivy, import every file
# into a new assessment, and write the two reports to lab/out. Only Juice Shop, on the lab's own
# network, is scanned. Needs Docker with the compose plugin, and lab/.env (see lab/.env.example).
set -euo pipefail
cd "$(dirname "$0")"

TARGET_IP=172.30.0.10
TARGET_URL="http://${TARGET_IP}:3000"
IMAGE=bkimminich/juice-shop:v17.1.1

[[ -f .env ]] || { echo "Copy lab/.env.example to lab/.env and fill it in first." >&2; exit 2; }
mkdir -p out
chmod 0777 out # the scanner runs as its own user and writes here

say() { printf '\n== %s\n' "$*"; }

say "Starting PostgreSQL, the API, the web app and Juice Shop"
docker compose up -d --build postgres api web juice-shop

wait_for() { # url, what
  for _ in $(seq 1 90); do
    curl -fsS -o /dev/null "$1" && return 0
    sleep 2
  done
  echo "$2 did not come up at $1" >&2
  exit 1
}
wait_for http://127.0.0.1:3001/health "The API"
wait_for http://127.0.0.1:3000 "Juice Shop"

say "Building the scanner image (the first time takes a few minutes)"
docker compose --profile scan build scanner

say "Nmap: versions and the vulners script on Juice Shop's port"
docker compose run --rm scanner nmap -sV --script vulners -p 3000 -oX /zap/wrk/nmap.xml "$TARGET_IP" >/dev/null

say "Nuclei: the community templates against the app"
docker compose run --rm scanner nuclei -u "$TARGET_URL" -jsonl -o /zap/wrk/nuclei.jsonl -silent -disable-update-check || true

say "ZAP baseline: a passive scan, no attacks sent"
# zap-baseline exits 1 or 2 when it finds something; that is a result, not a failure.
docker compose run --rm scanner zap-baseline.py -t "$TARGET_URL" -J zap.json -I >/dev/null || true

say "Trivy: the Juice Shop image, from a saved copy (no Docker socket handed to a container)"
docker save "$IMAGE" -o out/juice-shop-image.tar
docker run --rm -v "$PWD/out:/out" aquasec/trivy:0.57.1 image --input /out/juice-shop-image.tar --format json --output /out/trivy.json --quiet
rm -f out/juice-shop-image.tar

retest() { docker compose exec -T -e RETEST_TOKEN="$TOKEN" api node apps/cli/dist/cli.js "$@"; }

say "A token for this run, and a new assessment"
TOKEN=$(docker compose exec -T api node apps/api/dist/token.js "${USER:-lab}" assessor 2)
ID=$(retest new --name "Juice Shop lab $(date +%Y-%m-%d)" --client "Retest lab" \
  --target "$TARGET_IP" --target "$TARGET_URL" --target "$IMAGE" \
  --authorized-by "${USER:-lab}")
echo "Assessment $ID"

say "Importing"
retest import --tool nmap /lab-out/nmap.xml --assessment "$ID"
if [[ -s out/nuclei.jsonl ]]; then
  retest import --tool nuclei /lab-out/nuclei.jsonl --assessment "$ID"
else
  echo "Nuclei found nothing to import."
fi
retest import --tool zap /lab-out/zap.json --assessment "$ID"
retest import --tool trivy /lab-out/trivy.json --assessment "$ID"

say "Reports"
retest report "$ID" > out/report.md
retest report "$ID" --summary > out/summary.md
echo "Wrote lab/out/report.md and lab/out/summary.md."
echo "Open http://127.0.0.1:8080, connect with this token (valid two hours), and open the assessment:"
echo "$TOKEN"
echo
echo "Semgrep and Prowler are not part of this run: Semgrep needs the Juice Shop source checked out, and Prowler needs a cloud account you own."
