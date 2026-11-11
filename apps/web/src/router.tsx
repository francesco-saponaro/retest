import { QueryClientProvider, type QueryClient } from "@tanstack/react-query";
import { createRootRouteWithContext, createRoute, createRouter, notFound, Outlet, type RouterHistory } from "@tanstack/react-router";
import { OWASP_TOP_10_2021_IDS, PHASES, SEVERITIES, TOOLS } from "@retest/schema";
import { ApiError, type ApiClient, type FindingFilter } from "./api/client.js";
import { assessmentQuery, assessmentsQuery, assetsQuery, findingQuery, findingsQuery, importsQuery } from "./queries.js";
import { Assessments, AssessmentsFailed } from "./screens/Assessments.js";
import { Connect } from "./screens/Connect.js";
import { Finding, FindingFailed, FindingNotFound } from "./screens/Finding.js";
import { Findings, FindingsFailed } from "./screens/Findings.js";
import { Overview, OverviewFailed, OverviewNotFound } from "./screens/Overview.js";
import { Shell } from "./screens/Shell.js";

export interface RouterContext {
  client: ApiClient;
  queryClient: QueryClient;
}

/**
 * The routes, written in code: `/` the assessments, `/a/:id` one assessment's overview,
 * `/a/:id/findings` its findings table, `/a/:id/findings/:fid` one finding, `/connect` the token for
 * the API. Each loader fills the query cache so the screen renders with its data, and a 404 from
 * the API becomes the route's not-found view rather than a broken page.
 */
export const rootRoute = createRootRouteWithContext<RouterContext>()({
  component: () => (
    <Shell>
      <Outlet />
    </Shell>
  ),
});

export const assessmentsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/",
  loader: ({ context }) => context.queryClient.ensureQueryData(assessmentsQuery(context.client)),
  component: Assessments,
  errorComponent: AssessmentsFailed,
});

/** The assessment, or the route's not-found view when the API says it is not there (or not ours). */
async function ensureAssessment(context: RouterContext, id: string) {
  try {
    return await context.queryClient.ensureQueryData(assessmentQuery(context.client, id));
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) throw notFound();
    throw e;
  }
}

export const assessmentRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/a/$id",
  loader: async ({ context, params }) => {
    await ensureAssessment(context, params.id);
    // The rest of the screen loads in its own blocks; start them now so they are usually there on arrival.
    void context.queryClient.prefetchQuery(assetsQuery(context.client, params.id));
    void context.queryClient.prefetchQuery(importsQuery(context.client, params.id));
  },
  component: Overview,
  errorComponent: OverviewFailed,
  notFoundComponent: OverviewNotFound,
});

function oneOf<T extends string>(value: unknown, allowed: readonly T[]): T | undefined {
  return typeof value === "string" && (allowed as readonly string[]).includes(value) ? (value as T) : undefined;
}

/** The table's filters live in the URL, so a filtered list can be linked to and the back button undoes a filter. Anything unknown is dropped. */
export function findingSearch(raw: Record<string, unknown>): FindingFilter {
  const out: FindingFilter = {};
  const severity = oneOf(raw.severity, SEVERITIES);
  const tool = oneOf(raw.tool, TOOLS);
  const phase = oneOf(raw.phase, PHASES);
  const owasp = oneOf(raw.owasp, OWASP_TOP_10_2021_IDS);
  if (severity) out.severity = severity;
  if (tool) out.tool = tool;
  if (phase) out.phase = phase;
  if (owasp) out.owasp = owasp;
  if (typeof raw.assetId === "string" && raw.assetId) out.assetId = raw.assetId.slice(0, 200);
  if (typeof raw.q === "string" && raw.q.trim()) out.q = raw.q.trim().slice(0, 200);
  return out;
}

export const findingsRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/a/$id/findings",
  validateSearch: findingSearch,
  loaderDeps: ({ search }) => search,
  loader: async ({ context, params, deps }) => {
    await ensureAssessment(context, params.id);
    void context.queryClient.prefetchQuery(assetsQuery(context.client, params.id));
    void context.queryClient.prefetchQuery(findingsQuery(context.client, params.id, deps));
  },
  component: Findings,
  errorComponent: FindingsFailed,
  notFoundComponent: OverviewNotFound,
});

export const findingRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/a/$id/findings/$fid",
  loader: async ({ context, params }) => {
    await ensureAssessment(context, params.id);
    try {
      const f = await context.queryClient.ensureQueryData(findingQuery(context.client, params.fid));
      // A finding is reached by its own id; one that belongs to another assessment is not this page.
      if (f.assessmentId !== params.id) throw notFound();
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) throw notFound();
      throw e;
    }
  },
  component: Finding,
  errorComponent: FindingFailed,
  notFoundComponent: FindingNotFound,
});

export const connectRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/connect",
  component: Connect,
});

const routeTree = rootRoute.addChildren([assessmentsRoute, assessmentRoute, findingsRoute, findingRoute, connectRoute]);

export function createAppRouter(options: { client: ApiClient; queryClient: QueryClient; history?: RouterHistory }) {
  const router = createRouter({
    routeTree,
    context: { client: options.client, queryClient: options.queryClient },
    ...(options.history ? { history: options.history } : {}),
    defaultPreload: "intent",
    defaultPendingMs: 200,
    scrollRestoration: true,
    Wrap: ({ children }) => <QueryClientProvider client={options.queryClient}>{children}</QueryClientProvider>,
  });
  return router;
}

declare module "@tanstack/react-router" {
  interface Register {
    router: ReturnType<typeof createAppRouter>;
  }
}
