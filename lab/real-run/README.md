# A real run, 18 Nov 2026

The files in `packages/parsers/fixtures/` are sample files: written by hand in each tool's real format and trimmed to a handful of results, so the tests can count every one. The files in this folder are not. They are the unedited output of real scanners run against a real OWASP Juice Shop, and the demo imports them as a third assessment, "Juice Shop, real scan".

Juice Shop is a web shop built to be insecure on purpose, which is why it is safe and legal to scan: it runs in my own lab, on a private Docker network, and nothing else is touched.

## The lab run: Nmap, Nuclei, ZAP and Trivy

All five ran on my laptop. These four ran through `lab/run.sh`: Windows 11, Ubuntu in WSL 2, Docker Desktop with its WSL integration turned on.

```
git clone https://github.com/francesco-saponaro/retest.git
cd retest
cp lab/.env.example lab/.env      # then fill in the secrets
bash lab/run.sh 2>&1 | tee ~/lab-run.log
```

The script starts PostgreSQL, the API, the web app and Juice Shop 17.1.1 (172.30.0.10 on the lab network), builds a scanner image (ZAP 2.15.0 with Nmap and Nuclei 3.3.7 added), runs the four tools against Juice Shop only, and imports every file into a new assessment. What each one ran and found:

| Tool | Command | Raw results | In Retest |
| --- | --- | --- | --- |
| Nmap 7.80 | `nmap -sV --script vulners -p 3000 -oX nmap.xml 172.30.0.10` | port 3000 open | 1 finding |
| Nuclei 3.3.7 | `nuclei -u http://172.30.0.10:3000 -jsonl -rate-limit 50` | 19 matches (18 info, 1 medium) | 19 findings |
| ZAP 2.15.0 | `zap-baseline.py -t http://172.30.0.10:3000 -J zap.json` (passive, no attacks) | 12 alerts | 10 new, 2 merged into Nuclei's |
| Trivy 0.57.1 | `trivy image --input juice-shop-image.tar --format json` | 515 rows (51 critical, 199 high) | 305 new, 210 merged |

The lab run gave 335 findings on 3 assets, the same number Retest's own `summary.md` printed at the end of the run.

A few things worth knowing about the results:

- **Nmap** could not name the service. It labels port 3000 "ppp" (the name in its port list) and keeps the raw HTTP answers as a fingerprint, which already show `Access-Control-Allow-Origin: *`. The `vulners` script needs a version string, an Express app does not send one, so no CVEs came from Nmap.
- **ZAP and Nuclei agree** on two missing headers: Content-Security-Policy, and Permissions-Policy (ZAP saw the old Feature-Policy header in its place). Retest merges ZAP's two alerts into the findings Nuclei had already opened instead of counting them twice.
- **Trivy** found most of the volume: old packages in the image's Debian 11 base (OpenSSL, libc) and in its Node modules. The top risks are sandbox escapes in `vm2` 3.9.17. Its 210 merges are the same CVE found again in another copy of the same package.

## Semgrep, on the source

Semgrep reads source code, and the lab only has Juice Shop's image, so it is not in `lab/run.sh`. I ran it on the same laptop right after, with Semgrep's own Docker image (1.185.0) and the public rules as they were that day:

```
cd ~
git clone --depth 1 -b v17.1.1 https://github.com/juice-shop/juice-shop.git
git clone --depth 1 https://github.com/semgrep/semgrep-rules.git
docker run --rm -v ~/juice-shop:/src -v ~/semgrep-rules:/rules -w /src semgrep/semgrep \
  semgrep scan --metrics=off --config /rules/javascript --config /rules/typescript \
  --sarif -o /src/semgrep-juice-shop.sarif routes lib server.ts models
```

203 rules, 107 files, 87 results. Retest folds them into 64 findings on one repository asset. Among them are the real Juice Shop flaws (SQL built from user input in `routes/login.ts` and `routes/search.ts`, a JWT signing key written in `lib/insecurity.ts`, `eval` on the user's own name, XML parsed with external entities on), next to plenty of noise (23 "file name is not a literal" hits, 12 style warnings).

Together: 399 findings on 4 assets, none validated yet. That is the point of the validation phase: a scanner's output is a list of things to check, not a list of vulnerabilities.

## What broke on the way, and the fixes

The first two attempts failed. Each fix is in the code now.

1. **The scanner image did not build.** The ZAP image is Debian 11, whose security archive had moved, so `apt-get` returned 404s for Nuclei's dependencies. The Dockerfile now installs only Nmap from apt and unzips the Nuclei release with Python.
2. **Juice Shop crashed under Nuclei** (exit code 139, a segfault), so ZAP then found nothing to scan ("No route to host"). Nuclei now runs at 50 requests a second at most, Juice Shop has `restart: unless-stopped`, the script waits for it to answer again after each tool, ZAP's output is no longer hidden, and a tool that writes no file is skipped instead of stopping the run.
3. **Real Nuclei output has `null` fields** (`"cve-id": null`) that the hand-written samples never had, and the parser refused them. It now drops null fields before checking the line.
4. **Trivy named the asset after the tar file** (`/out/juice-shop-image.tar`), so the image looked out of scope. Imports now take `--image` to give the image's real name.

## Evidence a person captured

`evidence-cors.txt` is a curl with a foreign `Origin` header against the running app; `evidence-npm-ls.txt` shows which jsonwebtoken versions are installed (my home folder shortened to `~`). The sample assessment's walk-through uses these two outputs as its evidence.

## Still a sample

Prowler checks a cloud account's settings, so it only makes sense against a cloud account I own. The sample's account id, 123456789012, is AWS's documentation placeholder.
