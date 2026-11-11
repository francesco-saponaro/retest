import { QueryClient } from "@tanstack/react-query";
import { createMemoryHistory, RouterProvider } from "@tanstack/react-router";
import { cleanup, render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import { ApiError, type ApiClient } from "../src/api/client.js";
import { createAppRouter } from "../src/router.js";
import { fakeClient, juiceFive } from "./fake.js";
import { manyFindings } from "./findings.js";

function mount(path: string, client: ApiClient = fakeClient()) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const router = createAppRouter({ client, queryClient, history: createMemoryHistory({ initialEntries: [path] }) });
  render(<RouterProvider router={router} />);
  return router;
}

/** The fake client with an assessment whose totals agree with its five findings. */
function fiveClient(overrides: Partial<ApiClient> = {}): ApiClient {
  return fakeClient({ getAssessment: async (id) => (id === "a-juice" ? juiceFive : Promise.reject(new ApiError(404, "assessment not found"))), ...overrides });
}

describe("/ (assessments)", () => {
  it("names the product and lists every assessment with its phase and status", async () => {
    mount("/");
    expect(await screen.findByRole("heading", { level: 1, name: "Assessments" })).toBeInTheDocument();
    expect(screen.getByText("Retest")).toBeInTheDocument();
    const rows = within(screen.getByRole("table", { name: "Assessments" })).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(2);
    expect(within(rows[0]!).getByRole("link", { name: "Juice Shop lab" })).toHaveAttribute("href", "/a/a-juice");
    expect(within(rows[0]!).getByText("3 of 6 · Vulnerability assessment")).toBeInTheDocument();
    expect(within(rows[0]!).getByText("active")).toBeInTheDocument();
    expect(within(rows[1]!).getByText("2 of 6 · Reconnaissance and discovery")).toBeInTheDocument();
    expect(screen.getByText(/^2 assessments/)).toBeInTheDocument();
  });

  it("keeps the frame and says so when there is nothing yet", async () => {
    mount("/", fakeClient({ listAssessments: async () => [] }));
    expect(await screen.findByText("No assessments yet.")).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1, name: "Assessments" })).toBeInTheDocument();
  });

  it("shows the failure inside the block, with a retry", async () => {
    let calls = 0;
    const client = fakeClient({
      listAssessments: async () => {
        calls += 1;
        if (calls === 1) throw new Error("connection refused");
        return [];
      },
    });
    mount("/", client);
    expect(await screen.findByText(/Couldn't load the assessments/)).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByText("No assessments yet.")).toBeInTheDocument();
  });

  it("opens an assessment from its row", async () => {
    const router = mount("/");
    await userEvent.click(await screen.findByRole("link", { name: "Juice Shop lab" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Juice Shop lab" })).toBeInTheDocument();
    expect(router.state.location.pathname).toBe("/a/a-juice");
  });
});

describe("/a/:id (overview)", () => {
  it("leads with the assessment's name, its phase and how much is still unverified", async () => {
    mount("/a/a-juice");
    expect(await screen.findByRole("heading", { level: 1, name: "Juice Shop lab" })).toBeInTheDocument();
    expect(screen.getByText("37 findings on 5 assets, and all 37 are still what a scanner said: none has reached validation.")).toBeInTheDocument();
  });

  it("draws the six-phase board with the current phase marked and the findings in each", async () => {
    mount("/a/a-juice");
    const board = await screen.findByRole("list", { name: "The six phases" });
    const cells = within(board).getAllByRole("listitem");
    expect(cells.map((c) => c.getAttribute("aria-current"))).toEqual([null, null, "step", null, null, null]);
    expect(within(cells[1]!).getByText("Reconnaissance and discovery")).toBeInTheDocument();
    expect(within(cells[1]!).getByText("4")).toBeInTheDocument();
    expect(within(cells[2]!).getByText("33")).toBeInTheDocument();
    expect(within(cells[3]!).getByText("0")).toBeInTheDocument();
  });

  it("totals the findings by severity, in the order a report lists them", async () => {
    mount("/a/a-juice");
    const strip = await screen.findByRole("group", { name: "Findings by severity" });
    const cells = within(strip).getAllByRole("listitem");
    expect(cells.map((c) => c.textContent)).toEqual(["Critical4", "High7", "Medium11", "Low3", "Informational12"]);
  });

  it("lists the scope, the assets with their coverage and the imports with their counts", async () => {
    mount("/a/a-juice");
    expect(await screen.findByText("5 targets, no exclusions · authorised by francesco on 2026-11-10")).toBeInTheDocument();
    const scope = screen.getByRole("table", { name: "Scope" });
    expect(within(scope).getAllByRole("row")).toHaveLength(6);
    expect(within(within(scope).getByRole("row", { name: /^127\.0\.0\.1 / })).getByText("2 assets")).toBeInTheDocument();
    expect(within(within(scope).getByRole("row", { name: /juice-shop / })).getByText("1 asset")).toBeInTheDocument();
    const assets = screen.getByRole("table", { name: "Assets" });
    expect(within(assets).getAllByRole("row")).toHaveLength(6);
    expect(within(assets).getByText("Out of scope")).toBeInTheDocument();
    const imports = screen.getByRole("table", { name: "Imports" });
    const zap = within(imports).getByRole("row", { name: /zap/ });
    const cells = within(zap).getAllByRole("cell").map((c) => c.textContent);
    expect(cells).toContain("6");
    expect(cells.filter((c) => c === "3")).toHaveLength(2);
    expect(within(imports).getByText("finding 7 is MANUAL: not imported")).toBeInTheDocument();
  });

  it("says when the assessment is not there", async () => {
    mount("/a/a-nope");
    expect(await screen.findByText("This assessment is not here, or it is not yours.")).toBeInTheDocument();
  });
});

describe("/a/:id/findings (the table)", () => {
  it("leads with what is shown and lists every finding, most severe first, with a link to each", async () => {
    mount("/a/a-juice/findings", fiveClient());
    expect(await screen.findByRole("heading", { level: 1, name: "Findings" })).toBeInTheDocument();
    expect(screen.getByText("5 findings: 2 critical, 1 high, 1 medium; none has reached validation.")).toBeInTheDocument();
    const table = screen.getByRole("table", { name: "Findings" });
    const rows = within(table).getAllByRole("row").filter((r) => r.querySelector("td.id"));
    expect(rows).toHaveLength(5);
    expect(within(rows[0]!).getByRole("link", { name: /CVE-2015-9235/ })).toHaveAttribute("href", "/a/a-juice/findings/f-jwt");
    expect(within(rows[0]!).getByText("Critical")).toBeInTheDocument();
    expect(within(rows[0]!).getByText("jsonwebtoken@0.4.0")).toBeInTheDocument();
    expect(within(rows[0]!).getByText("9.8")).toBeInTheDocument();
    const cors = within(table).getByRole("row", { name: /CORS Misconfiguration/ });
    expect(within(cors).getByText("nuclei, zap")).toBeInTheDocument();
    expect(within(cors).getByText("A01, A05")).toBeInTheDocument();
    expect(within(cors).getByText("2")).toBeInTheDocument();
    const http = within(table).getByRole("row", { name: /http on tcp\/3000/ });
    expect(within(http).getByText("Recon")).toBeInTheDocument();
  });

  it("filters from the URL and writes the filters back to it", async () => {
    const router = mount("/a/a-juice/findings?severity=critical", fiveClient());
    expect(await screen.findByText("2 of 5 findings match: 2 critical; none has reached validation.")).toBeInTheDocument();
    expect(screen.getByRole("combobox", { name: "Severity" })).toHaveValue("critical");
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Tool" }), "prowler");
    expect(await screen.findByText("1 of 5 findings match: 1 critical; none has reached validation.")).toBeInTheDocument();
    expect(router.state.location.search).toEqual({ severity: "critical", tool: "prowler" });
    await userEvent.click(screen.getByRole("button", { name: "Clear" }));
    expect(await screen.findByText("5 findings: 2 critical, 1 high, 1 medium; none has reached validation.")).toBeInTheDocument();
    expect(router.state.location.search).toEqual({});
  });

  it("searches the title and the scope", async () => {
    mount("/a/a-juice/findings", fiveClient());
    const box = await screen.findByRole("searchbox", { name: "Search" });
    await userEvent.type(box, "login.ts{enter}");
    expect(await screen.findByText("1 of 5 findings match: 1 high; none has reached validation.")).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /express-sequelize-injection/ })).toBeInTheDocument();
  });

  it("offers the assets and the OWASP categories of this assessment as filters", async () => {
    mount("/a/a-juice/findings", fiveClient());
    const asset = await screen.findByRole("combobox", { name: "Asset" });
    expect(within(asset).getAllByRole("option").map((o) => o.textContent)).toEqual(["Any asset", "127.0.0.1", "http://127.0.0.1:3000", "juice-shop", "bkimminich/juice-shop:v17.1.1", "123456789012"]);
    await userEvent.selectOptions(asset, "asset-repo-juice-shop");
    expect(await screen.findByText("1 of 5 findings match: 1 high; none has reached validation.")).toBeInTheDocument();
    const owasp = screen.getByRole("combobox", { name: "OWASP Top 10" });
    expect(within(owasp).getAllByRole("option")).toHaveLength(11);
    expect(within(owasp).getByRole("option", { name: "A03 Injection" })).toBeInTheDocument();
  });

  it("keeps the frame and says so when nothing matches, and when nothing was imported", async () => {
    mount("/a/a-juice/findings?q=nothing-like-this", fiveClient());
    expect(await screen.findByText("0 of 5 findings match.")).toBeInTheDocument();
    expect(screen.getByText("No findings match these filters.")).toBeInTheDocument();
    cleanup();
    mount("/a/a-juice/findings", fakeClient({ getAssessment: async () => ({ ...juiceFive, totals: { ...juiceFive.totals, findings: 0, bySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } } }), listFindings: async () => ({ items: [], total: 0, limit: 500, offset: 0 }) }));
    expect(await screen.findByText("No findings yet: nothing has been imported.")).toBeInTheDocument();
  });

  it("renders only the rows in view when there are hundreds", async () => {
    const items = manyFindings(600);
    mount("/a/a-juice/findings", fakeClient({ getAssessment: async () => ({ ...juiceFive, totals: { ...juiceFive.totals, findings: 600 } }), listFindings: async () => ({ items: items.slice(0, 500), total: 600, limit: 500, offset: 0 }) }));
    expect(await screen.findByText("The first 500 of 600 findings; narrow them with the filters.")).toBeInTheDocument();
    const table = screen.getByRole("table", { name: "Findings" });
    const rows = within(table).getAllByRole("row").filter((r) => r.querySelector("td.id"));
    expect(rows.length).toBeGreaterThan(5);
    expect(rows.length).toBeLessThan(100);
  });

  it("shows the failure inside the table's frame with a retry", async () => {
    let up = false;
    const base = fakeClient();
    mount(
      "/a/a-juice/findings",
      fiveClient({
        listFindings: async (id, f) => {
          if (!up) throw new Error("connection refused");
          return base.listFindings(id, f);
        },
      }),
    );
    expect(await screen.findByText(/Couldn't load the findings: connection refused/)).toBeInTheDocument();
    up = true;
    await userEvent.click(screen.getByRole("button", { name: "Retry" }));
    expect(await screen.findByRole("link", { name: /CVE-2015-9235/ })).toBeInTheDocument();
  });

  it("is reached from the overview", async () => {
    mount("/a/a-juice");
    await userEvent.click(await screen.findByRole("link", { name: "All 37 findings" }));
    expect(await screen.findByRole("heading", { level: 1, name: "Findings" })).toBeInTheDocument();
  });
});

describe("/a/:id/findings/:fid (one finding)", () => {
  it("titles the finding and says where it stands", async () => {
    mount("/a/a-juice/findings/f-jwt");
    expect(await screen.findByRole("heading", { level: 1, name: "CVE-2015-9235 in jsonwebtoken 0.4.0" })).toBeInTheDocument();
    expect(screen.getByRole("heading", { level: 1 })).toHaveAttribute("title", "CVE-2015-9235 in jsonwebtoken 0.4.0: Verification Bypass in jsonwebtoken");
    expect(screen.getByText(/^Critical on bkimminich\/juice-shop:v17\.1\.1, reported by trivy .*nobody has validated it\.$/)).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Findings" })).toHaveAttribute("href", "/a/a-juice/findings");
  });

  it("lists the seven fields in the roadmap's order and marks the ones a tool cannot write", async () => {
    mount("/a/a-juice/findings/f-login");
    const list = await screen.findByRole("list", { name: "The seven fields" });
    const terms = within(list).getAllByRole("term").map((t) => t.textContent);
    expect(terms).toEqual(["Title", "Asset and scope", "Impact", "Evidence", "Risk", "Fix", "Retest"]);
    const defs = within(list).getAllByRole("definition");
    expect(defs[1]).toHaveTextContent("juice-shop");
    expect(defs[1]).toHaveTextContent("routes/login.ts:34-36");
    expect(defs[2]).toHaveTextContent("Not written yet");
    expect(defs[2]).toHaveTextContent("Not assessed yet. The scanner reported this; the impact is written after validation.");
    expect(defs[3]).toHaveTextContent("1 piece, not redacted: it stays out of the report until it is.");
    expect(defs[4]).toHaveTextContent("High");
    expect(defs[4]).toHaveTextContent("no CVSS vector");
    expect(defs[5]).toHaveTextContent("Not written yet");
    expect(defs[6]).toHaveTextContent("No retest yet");
  });

  it("shows a request and its response side by side and flags the line that carries a credential", async () => {
    mount("/a/a-juice/findings/f-cors");
    const section = await screen.findByRole("region", { name: "Evidence" });
    const pieces = within(section).getAllByRole("article");
    expect(pieces).toHaveLength(2);
    expect(within(pieces[0]!).getByRole("heading", { name: "GET http://127.0.0.1:3000/rest/products/search?q=" })).toBeInTheDocument();
    expect(within(pieces[0]!).getByText("Request")).toBeInTheDocument();
    expect(within(pieces[0]!).getByText("Response")).toBeInTheDocument();
    expect(within(pieces[0]!).getByText(/Access-Control-Allow-Origin: \*/)).toBeInTheDocument();
    expect(within(pieces[0]!).getByText("Not redacted")).toBeInTheDocument();
    expect(within(pieces[0]!).getByText("Line 4 carries a Cookie header: remove it before this goes in the report.")).toBeInTheDocument();
    expect(within(pieces[1]!).getByText("Redacted")).toBeInTheDocument();
    expect(within(pieces[1]!).getByText("3 instances reported by ZAP")).toBeInTheDocument();
  });

  it("names every tool that reported it, with what it claimed and where to read more", async () => {
    mount("/a/a-juice/findings/f-cors");
    const table = await screen.findByRole("table", { name: "Sources" });
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(2);
    expect(within(rows[0]!).getByText("nuclei")).toBeInTheDocument();
    expect(within(rows[0]!).getByText("cors-misconfig:arbitrary-origin")).toBeInTheDocument();
    expect(within(rows[0]!).getByText("low")).toBeInTheDocument();
    const link = within(rows[1]!).getByRole("link", { name: "zaproxy.org" });
    expect(link).toHaveAttribute("href", "https://www.zaproxy.org/docs/alerts/10098/");
    expect(link).toHaveAttribute("rel", "noopener noreferrer");
    const standards = screen.getByRole("list", { name: "Standards" });
    expect(within(standards).getByText("CWE-942, CWE-264")).toBeInTheDocument();
    expect(within(standards).getByText("A01 Broken Access Control, A05 Security Misconfiguration")).toBeInTheDocument();
    expect(within(standards).getByText("API8 Security Misconfiguration")).toBeInTheDocument();
  });

  it("scores a vector as the schema does, starting from the finding's own, and compares it with the tools' claims", async () => {
    mount("/a/a-juice/findings/f-jwt");
    const calc = await screen.findByRole("region", { name: "CVSS calculator" });
    expect(within(calc).getByRole("textbox", { name: "Vector" })).toHaveValue("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(within(calc).getByText("9.8")).toBeInTheDocument();
    expect(within(calc).getByText("trivy: 9.8, the same vector")).toBeInTheDocument();
    await userEvent.click(within(calc).getByRole("radio", { name: "Availability: None" }));
    expect(within(calc).getByRole("textbox", { name: "Vector" })).toHaveValue("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N");
    expect(within(calc).getByText("9.1")).toBeInTheDocument();
    expect(within(calc).getByText("trivy: 9.8 from CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")).toBeInTheDocument();
    expect(within(calc).getByText("Impact 5.2 · Exploitability 3.9")).toBeInTheDocument();
  });

  it("takes a pasted vector, refuses a bad one in words, and stores the risk on the finding", async () => {
    const client = fakeClient();
    mount("/a/a-juice/findings/f-cors", client);
    const calc = await screen.findByRole("region", { name: "CVSS calculator" });
    const box = within(calc).getByRole("textbox", { name: "Vector" });
    expect(box).toHaveValue("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N");
    expect(within(calc).getByText("0.0")).toBeInTheDocument();
    await userEvent.clear(box);
    await userEvent.type(box, "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N");
    expect(within(calc).getByText(/metric A is missing/)).toBeInTheDocument();
    await userEvent.type(box, "/A:N");
    expect(within(calc).getByText("7.5")).toBeInTheDocument();
    expect(within(calc).getByText("High", { selector: ".word" })).toBeInTheDocument();
    await userEvent.click(within(calc).getByRole("button", { name: "Use as the finding's risk" }));
    expect(await within(calc).findByText("Stored as the finding's risk.")).toBeInTheDocument();
    const stored = await client.getFinding("f-cors");
    expect(stored.risk).toEqual({ severity: "high", cvss: { vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N", baseScore: 7.5 } });
    const list = screen.getByRole("list", { name: "The seven fields" });
    expect(within(list).getAllByRole("definition")[4]).toHaveTextContent("High");
  });

  it("says when the finding is not there", async () => {
    mount("/a/a-juice/findings/f-nope");
    expect(await screen.findByText("This finding is not here, or it is not yours.")).toBeInTheDocument();
  });
});
