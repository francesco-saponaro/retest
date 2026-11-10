import { QueryClient } from "@tanstack/react-query";
import { createMemoryHistory, RouterProvider } from "@tanstack/react-router";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import type { ApiClient } from "../src/api/client.js";
import { createAppRouter } from "../src/router.js";
import { fakeClient } from "./fake.js";

function mount(path: string, client: ApiClient = fakeClient()) {
  const queryClient = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const router = createAppRouter({ client, queryClient, history: createMemoryHistory({ initialEntries: [path] }) });
  render(<RouterProvider router={router} />);
  return router;
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
