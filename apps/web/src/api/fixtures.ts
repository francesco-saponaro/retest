import nmapJuiceShop from "../../../../packages/parsers/fixtures/nmap/juice-shop.xml?raw";
import nmapLabVms from "../../../../packages/parsers/fixtures/nmap/lab-vms.xml?raw";
import nucleiJuiceShop from "../../../../packages/parsers/fixtures/nuclei/juice-shop.jsonl?raw";
import prowlerLabAccount from "../../../../packages/parsers/fixtures/prowler/lab-account.ocsf.json?raw";
import semgrepJuiceShop from "../../../../packages/parsers/fixtures/semgrep/juice-shop.sarif?raw";
import trivyJuiceShopImage from "../../../../packages/parsers/fixtures/trivy/juice-shop-image.json?raw";
import zapJuiceShop from "../../../../packages/parsers/fixtures/zap/juice-shop.json?raw";
import realNmap from "../../../../lab/real-run/nmap.xml?raw";
import realNuclei from "../../../../lab/real-run/nuclei.jsonl?raw";
import realZap from "../../../../lab/real-run/zap.json?raw";
import realTrivy from "../../../../lab/real-run/trivy.json?raw";
import realSemgrep from "../../../../lab/real-run/semgrep-juice-shop.sarif?raw";

/**
 * The scanner output the demo imports, bundled as text at build time. These are the same files
 * `packages/parsers/fixtures/` holds and the API's seed reads from disk, keyed by that path.
 */
export const FIXTURES: Record<string, string> = {
  "nmap/juice-shop.xml": nmapJuiceShop,
  "nmap/lab-vms.xml": nmapLabVms,
  "nuclei/juice-shop.jsonl": nucleiJuiceShop,
  "zap/juice-shop.json": zapJuiceShop,
  "semgrep/juice-shop.sarif": semgrepJuiceShop,
  "trivy/juice-shop-image.json": trivyJuiceShopImage,
  "prowler/lab-account.ocsf.json": prowlerLabAccount,
};

/** The unedited output of a real run against Juice Shop on 18 Nov 2026 (see `lab/real-run/README.md`). */
export const REAL_RUN: Record<string, string> = {
  "real-run/nmap.xml": realNmap,
  "real-run/nuclei.jsonl": realNuclei,
  "real-run/zap.json": realZap,
  "real-run/trivy.json": realTrivy,
  "real-run/semgrep-juice-shop.sarif": realSemgrep,
};
