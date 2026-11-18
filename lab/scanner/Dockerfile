# The scanners the lab runs against Juice Shop: ZAP's baseline scan (the base image), Nmap with
# version detection and the vulners script, and Nuclei with its templates fetched at build time.
FROM zaproxy/zap-stable:2.15.0
USER root
ARG NUCLEI_VERSION=3.3.7
# Only Nmap comes from apt: the base image's Debian 11 security archive no longer serves newer curl,
# unzip or ca-certificates, and the image already has curl, certificates and Python to unzip with.
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap \
 && curl -fsSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
 && python3 -m zipfile -e /tmp/nuclei.zip /tmp/nuclei \
 && install -m 0755 /tmp/nuclei/nuclei /usr/local/bin/nuclei \
 && rm -rf /tmp/nuclei /tmp/nuclei.zip /var/lib/apt/lists/*
USER zap
RUN nuclei -update-templates -silent
WORKDIR /zap/wrk
