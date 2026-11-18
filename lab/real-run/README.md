# A real run, 18 Nov 2026

The files in `packages/parsers/fixtures/` are sample files: written by hand in each tool's real format and trimmed to a handful of results, so the tests can count every one. The files in this folder are not. They are the unedited output of real scanners run against a real OWASP Juice Shop on my own machine, and the demo imports them as a third assessment, "Juice Shop, real scan".

## What ran, and how

Everything ran on one Ubuntu 24.04 machine, against 127.0.0.1 only. Juice Shop is built to be insecure, which is why it is safe and legal to scan: it is mine, it runs on my machine, and nothing else is touched.

**1. Juice Shop 17.1.1, from source**

```
git clone --depth 1 -b v17.1.1 https://github.com/juice-shop/juice-shop.git
cd juice-shop
CYPRESS_INSTALL_BINARY=0 npm install     # Node 22; builds the frontend and the server
npm start                                # http://127.0.0.1:3000
```

**2. Nmap 7.94, service detection on Juice Shop's port**

```
nmap -sV --script vulners,http-headers,http-title -p 3000 -oX nmap-juice-shop.xml 127.0.0.1
```

Only port 3000, because the machine runs other things that are not in scope. Two honest results worth knowing:

- Nmap could not name the service. It labels port 3000 "ppp" (the name in its port list) and keeps the raw HTTP answers as a fingerprint. Those answers already show something useful: `Access-Control-Allow-Origin: *` on every response.
- The `vulners` script needs a version string to look up, and an Express app does not give one, so it found nothing. A banner is not a version, and no version means no CVE match.

Retest reads this as one inventory line, `ppp on tcp/3000`, in phase 2.

**3. Semgrep 1.186, on the server code**

```
git clone --depth 1 https://github.com/semgrep/semgrep-rules.git      # the public rules, at a5ad171
cd juice-shop
semgrep scan --metrics=off \
  --config ../semgrep-rules/javascript --config ../semgrep-rules/typescript \
  --sarif -o semgrep-juice-shop.sarif routes lib server.ts models
```

203 rules, 250 files, 87 results. Retest folds them into 64 findings on one repository asset. Among them are the real Juice Shop flaws (SQL built from user input in `routes/login.ts` and `routes/search.ts`, a JWT signing key and an HMAC key written in `lib/insecurity.ts`, `eval` in two routes, one of them on the user's own name, and XML parsed with external entities on in `routes/fileUpload.ts`), next to plenty of noise (23 "file name is not a literal" hits, 12 style warnings). That mix is the point of the validation phase: a scanner's output is a list of things to check, not a list of vulnerabilities.

**4. Evidence a person captured**

`evidence-cors.txt` is a curl with a foreign `Origin` header against the running app; `evidence-npm-ls.txt` shows which jsonwebtoken versions are installed (my home folder shortened to `~`). The sample assessment's walk-through uses these two outputs as its evidence.

## What is still a sample, and why

| Tool | Here | Why |
| --- | --- | --- |
| Nmap | real | |
| Semgrep | real | |
| OWASP ZAP | sample | The machine could not download ZAP. `lab/run.sh` runs it on any machine with Docker. |
| Nuclei | sample | Same: no download of the binary or its templates. `lab/run.sh` runs it. |
| Trivy | sample | Trivy needs its vulnerability database from a container registry. `lab/run.sh` runs it. |
| Prowler | sample | Prowler needs a cloud account I own. The sample's account id, 123456789012, is AWS's documentation placeholder. |

To get real files for the other four, run `lab/run.sh` on a machine with Docker (see the main README): it starts Juice Shop and runs Nmap, Nuclei, ZAP and Trivy against it. Prowler only makes sense against your own cloud account.
