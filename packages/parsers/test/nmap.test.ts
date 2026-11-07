import { describe, expect, it } from "vitest";
import { nmapFindings, parseNmap, parseNmapXml } from "../src/nmap.js";
import { fixture } from "./helpers.js";

const juiceShop = fixture("nmap/juice-shop.xml");
const labVms = fixture("nmap/lab-vms.xml");

describe("parseNmapXml: the run", () => {
  const scan = parseNmapXml(juiceShop);

  it("reads the scanner, its version, the command line and the times", () => {
    expect(scan.scanner).toBe("nmap");
    expect(scan.version).toBe("7.95");
    expect(scan.args).toBe("nmap -sV -sC -p- -oX fixtures/nmap/juice-shop.xml 127.0.0.1");
    expect(scan.startedAt).toBe("2026-11-07T17:02:11.000Z");
    expect(scan.finishedAt).toBe("2026-11-07T17:02:36.000Z");
    expect(scan.summary).toContain("1 IP address (1 host up)");
    expect(scan.hostsUp).toBe(1);
    expect(scan.hostsTotal).toBe(1);
  });

  it("reads the host: address, names, state, open ports and the ports it did not list", () => {
    expect(scan.hosts).toHaveLength(1);
    const host = scan.hosts[0]!;
    expect(host.address).toBe("127.0.0.1");
    expect(host.addressType).toBe("ipv4");
    expect(host.hostnames).toEqual(["localhost"]);
    expect(host.state).toBe("up");
    expect(host.ports).toHaveLength(4);
    expect(host.ports.map((p) => p.port)).toEqual([22, 3000, 5432, 8080]);
    expect(host.extraPorts).toEqual([{ state: "closed", count: 65531 }]);
    expect(host.scripts).toEqual([]);
  });

  it("reads a port: protocol, state, reason, the service and its cpes", () => {
    const ssh = scan.hosts[0]!.ports[0]!;
    expect(ssh).toMatchObject({ protocol: "tcp", port: 22, state: "open", reason: "syn-ack" });
    expect(ssh.service).toEqual({
      name: "ssh",
      product: "OpenSSH",
      version: "9.6p1 Ubuntu 3ubuntu13.5",
      extraInfo: "Ubuntu Linux; protocol 2.0",
      osType: "Linux",
      method: "probed",
      confidence: 10,
      cpes: ["cpe:/a:openbsd:openssh:9.6p1", "cpe:/o:linux:linux_kernel"],
    });
  });

  it("reads a port with a product but no version", () => {
    const web = scan.hosts[0]!.ports[1]!;
    expect(web.port).toBe(3000);
    expect(web.service?.name).toBe("http");
    expect(web.service?.product).toBe("Node.js Express framework");
    expect(web.service?.version).toBeUndefined();
    expect(web.service?.cpes).toEqual(["cpe:/a:nodejs:node.js"]);
  });

  it("reads the NSE scripts of a port in order, with their output and their structured values", () => {
    const web = scan.hosts[0]!.ports[1]!;
    expect(web.scripts.map((s) => s.id)).toEqual(["http-title", "http-robots.txt", "http-cors", "http-server-header"]);
    expect(web.scripts[0]!.output).toBe("OWASP Juice Shop");
    expect(web.scripts[0]!.values).toEqual({ title: "OWASP Juice Shop" });
    expect(web.scripts[1]!.values).toEqual({ disallowed: "/ftp" });
    expect(web.scripts[2]!.values).toEqual(["HEAD", "GET", "POST", "PUT", "DELETE", "OPTIONS"]);
    expect(web.scripts[3]!.output).toBe("\n  Server header absent\n_  X-Powered-By: Express");
    expect(web.scripts[3]!.values).toBeUndefined();
  });

  it("reads nested script tables", () => {
    const ssh = scan.hosts[0]!.ports[0]!;
    expect(ssh.scripts).toHaveLength(1);
    const hostkey = ssh.scripts[0]!;
    expect(hostkey.id).toBe("ssh-hostkey");
    expect(hostkey.values).toEqual([
      expect.objectContaining({ type: "ecdsa-sha2-nistp256", bits: "256" }),
      expect.objectContaining({ type: "ssh-ed25519", bits: "256" }),
    ]);
  });
});

describe("parseNmapXml: two lab VMs, one of them down", () => {
  const scan = parseNmapXml(labVms);

  it("keeps the host that is down, with no ports", () => {
    expect(scan.hosts).toHaveLength(2);
    expect(scan.hostsUp).toBe(1);
    expect(scan.hostsTotal).toBe(2);
    const down = scan.hosts[1]!;
    expect(down.address).toBe("10.0.10.12");
    expect(down.state).toBe("down");
    expect(down.ports).toEqual([]);
    expect(down.hostnames).toEqual([]);
  });

  it("keeps the MAC address and its vendor", () => {
    const up = scan.hosts[0]!;
    expect(up.address).toBe("10.0.10.11");
    expect(up.mac).toEqual({ address: "08:00:27:4B:9C:E1", vendor: "Oracle VirtualBox virtual NIC" });
    expect(up.hostnames).toEqual(["lab-linux"]);
  });

  it("keeps a UDP port that is open|filtered as what it is", () => {
    const snmp = scan.hosts[0]!.ports.find((p) => p.protocol === "udp");
    expect(snmp).toMatchObject({ port: 161, state: "open|filtered", reason: "no-response" });
    expect(snmp?.service).toMatchObject({ name: "snmp", method: "table", confidence: 3 });
  });

  it("reads the vulners tables: one list of CVEs per cpe", () => {
    const http = scan.hosts[0]!.ports.find((p) => p.port === 80)!;
    const vulners = http.scripts.find((s) => s.id === "vulners")!;
    expect(vulners.values).toEqual({
      "cpe:/a:apache:http_server:2.4.52": [
        { id: "CVE-2022-31813", type: "cve", is_exploit: "false", cvss: "9.8" },
        { id: "CVE-2022-22720", type: "cve", is_exploit: "false", cvss: "9.8" },
        { id: "CVE-2022-30556", type: "cve", is_exploit: "false", cvss: "7.5" },
      ],
    });
  });

  it("reads host scripts separately from port scripts", () => {
    const up = scan.hosts[0]!;
    expect(up.scripts.map((s) => s.id)).toEqual(["smb-security-mode"]);
    expect(up.scripts[0]!.values).toMatchObject({ message_signing: "disabled (dangerous, but default)" });
  });
});

describe("parseNmapXml: bad input", () => {
  it("refuses XML that is not an Nmap run", () => {
    expect(() => parseNmapXml("<html><body>not a scan</body></html>")).toThrow(/not an Nmap XML report/);
  });

  it("refuses text that is not XML at all", () => {
    expect(() => parseNmapXml("Starting Nmap 7.95 ( https://nmap.org )")).toThrow(/not an Nmap XML report/);
  });

  it("accepts a run with no hosts", () => {
    const empty = `<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap -sV 10.0.10.12" start="1794073202" version="7.95"><runstats><finished time="1794073204" summary="Nmap done; 1 IP address (0 hosts up) scanned in 2.01 seconds"/><hosts up="0" down="1" total="1"/></runstats></nmaprun>`;
    const scan = parseNmapXml(empty);
    expect(scan.hosts).toEqual([]);
    expect(scan.hostsUp).toBe(0);
  });
});

describe("nmapFindings: the Juice Shop host", () => {
  const scan = parseNmapXml(juiceShop);
  const findings = nmapFindings(scan);

  it("makes exactly one raw finding per open port", () => {
    expect(findings).toHaveLength(4);
    expect(findings.map((f) => f.rawId)).toEqual(["tcp/22", "tcp/3000", "tcp/5432", "tcp/8080"]);
  });

  it("titles the finding with the service, the port and the product", () => {
    expect(findings.map((f) => f.title)).toEqual([
      "ssh on tcp/22 (OpenSSH 9.6p1 Ubuntu 3ubuntu13.5)",
      "http on tcp/3000 (Node.js Express framework)",
      "postgresql on tcp/5432 (PostgreSQL DB 16.4 - 16.10)",
      "http-proxy on tcp/8080 (OWASP ZAP)",
    ]);
  });

  it("points at the host and the port, in the recon phase, with no severity of its own", () => {
    const web = findings[1]!;
    expect(web.tool).toBe("nmap");
    expect(web.host).toBe("127.0.0.1");
    expect(web.port).toBe(3000);
    expect(web.protocol).toBe("tcp");
    expect(web.scope).toBe("tcp/3000");
    expect(web.phase).toBe("recon");
    expect(web.severity).toBeUndefined();
    expect(web.cve).toEqual([]);
    expect(web.cwe).toEqual([]);
    expect(web.detectedAt).toBe("2026-11-07T17:02:11.000Z");
  });

  it("carries the port line as Nmap prints it, then one evidence block per script", () => {
    const web = findings[1]!;
    expect(web.evidence[0]).toEqual({
      kind: "scanner-output",
      title: "nmap -sV -sC -p- -oX fixtures/nmap/juice-shop.xml 127.0.0.1",
      content: "3000/tcp open  http  Node.js Express framework",
    });
    expect(web.evidence.map((e) => e.title)).toEqual([
      "nmap -sV -sC -p- -oX fixtures/nmap/juice-shop.xml 127.0.0.1",
      "http-title",
      "http-robots.txt",
      "http-cors",
      "http-server-header",
    ]);
    expect(web.evidence[2]).toEqual({ kind: "command-output", title: "http-robots.txt", content: "1 disallowed entry \n/ftp" });
    expect(findings[0]!.evidence[0]!.content).toBe("22/tcp open  ssh  OpenSSH 9.6p1 Ubuntu 3ubuntu13.5 (Ubuntu Linux; protocol 2.0)");
  });

  it("tags the finding with the service name and the cpes", () => {
    expect(findings[0]!.tags).toEqual(["ssh", "cpe:/a:openbsd:openssh:9.6p1", "cpe:/o:linux:linux_kernel"]);
  });
});

describe("nmapFindings: the lab VMs", () => {
  const findings = nmapFindings(parseNmapXml(labVms));

  it("counts three open ports, two vulners matches and one weak SMB setting; nothing for the host that is down or the port that is open|filtered", () => {
    expect(findings).toHaveLength(6);
    expect(findings.map((f) => f.rawId)).toEqual([
      "tcp/22",
      "tcp/22/vulners",
      "tcp/80",
      "tcp/80/vulners",
      "tcp/445",
      "smb-security-mode",
    ]);
    expect(findings.every((f) => f.host === "10.0.10.11")).toBe(true);
  });

  it("turns a vulners table into one raw finding with the CVE list and the highest score", () => {
    const apache = findings.find((f) => f.rawId === "tcp/80/vulners")!;
    expect(apache.title).toBe("Known CVEs for Apache httpd 2.4.52 on tcp/80");
    expect(apache.cve).toEqual(["CVE-2022-31813", "CVE-2022-22720", "CVE-2022-30556"]);
    expect(apache.cvss).toEqual({ score: 9.8 });
    expect(apache.severity).toBeUndefined();
    expect(apache.phase).toBe("assessment");
    expect(apache.scope).toBe("tcp/80");
    expect(apache.references).toEqual([
      "https://vulners.com/cve/CVE-2022-31813",
      "https://vulners.com/cve/CVE-2022-22720",
      "https://vulners.com/cve/CVE-2022-30556",
    ]);
    expect(apache.impact).toMatch(/version/i);
    expect(apache.evidence).toHaveLength(1);
    expect(apache.evidence[0]!.title).toBe("vulners");
  });

  it("reports SMB signing that is not required as a finding on the host", () => {
    const smb = findings.find((f) => f.rawId === "smb-security-mode")!;
    expect(smb.title).toBe("SMB signing not required");
    expect(smb.scope).toBe("tcp/445");
    expect(smb.port).toBe(445);
    expect(smb.cwe).toEqual([924]);
    expect(smb.phase).toBe("assessment");
    expect(smb.evidence[0]!.content).toContain("message_signing: disabled");
  });

  it("leaves the port finding untouched by the vulners match", () => {
    const sshPort = findings.find((f) => f.rawId === "tcp/22")!;
    expect(sshPort.cve).toEqual([]);
    expect(sshPort.evidence.map((e) => e.title)).toEqual([
      "nmap -sS -sU -sV --script vulners,http-title,http-server-header,smb-security-mode -p T:22,80,445,U:161 -oX fixtures/nmap/lab-vms.xml 10.0.10.11 10.0.10.12",
      "vulners",
    ]);
  });
});

describe("parseNmap", () => {
  it("returns the tool, the findings, the scan and no warnings for a good file", () => {
    const result = parseNmap(juiceShop);
    expect(result.tool).toBe("nmap");
    expect(result.findings).toHaveLength(4);
    expect(result.scan.hosts).toHaveLength(1);
    expect(result.warnings).toEqual([]);
  });

  it("warns when every host was down", () => {
    const result = parseNmap(
      `<?xml version="1.0"?><nmaprun scanner="nmap" args="nmap 10.0.10.12" start="1794073202" version="7.95"><host><status state="down" reason="no-response"/><address addr="10.0.10.12" addrtype="ipv4"/></host><runstats><finished time="1794073204" summary="Nmap done"/><hosts up="0" down="1" total="1"/></runstats></nmaprun>`,
    );
    expect(result.findings).toEqual([]);
    expect(result.warnings).toEqual(["no host was up: 1 scanned, 0 up"]);
  });
});
