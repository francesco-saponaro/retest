# The scanners the lab runs against Juice Shop: ZAP's baseline scan (the base image), Nmap with
# version detection and the vulners script, and Nuclei with its templates fetched at build time.
FROM zaproxy/zap-stable:2.15.0
USER root
ARG NUCLEI_VERSION=3.3.7
RUN apt-get update \
 && apt-get install -y --no-install-recommends nmap unzip curl ca-certificates \
 && curl -fsSL -o /tmp/nuclei.zip "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
 && unzip -o /tmp/nuclei.zip nuclei -d /usr/local/bin \
 && rm /tmp/nuclei.zip \
 && apt-get purge -y unzip && apt-get autoremove -y && rm -rf /var/lib/apt/lists/*
USER zap
RUN nuclei -update-templates -silent
WORKDIR /zap/wrk
