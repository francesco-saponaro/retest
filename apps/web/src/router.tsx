import { QueryClientProvider, type QueryClient } from "@tanstack/react-query";
import { createRootRouteWithContext, createRoute, createRouter, notFound, Outlet, type RouterHistory } from "@tanstack/react-router";
import { ApiError, type ApiClient } from "./api/client.js";
import { assessmentQuery, assessmentsQuery, assetsQuery, importsQuery } from "./queries.js";
import { Assessments, AssessmentsFailed } from "./screens/Assessments.js";
import { Connect } from "./screens/Connect.js";
import { Overview, OverviewFailed, OverviewNotFound } from "./screens/Overview.js";
import { Shell } from "./screens/Shell.js";

export interface RouterContext {
  client: ApiClient;
  queryClient: QueryClient;
}

/**
 * The routes, written in code: `/` the assessments, `/a/:id` one assessment's overview, `/connect`
 * the token for the API. Each loader fills the query cache so the screen renders with its data,
 * and a 404 from the API becomes the route's not-found view rather than a broken page.
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

export const assessmentRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/a/$id",
  loader: async ({ context, params }) => {
    try {
      await context.queryClient.ensureQueryData(assessmentQuery(context.client, params.id));
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) throw notFound();
      throw e;
    }
    // The rest of the screen loads in its own blocks; start them now so they are usually there on arrival.
    void context.queryClient.prefetchQuery(assetsQuery(context.client, params.id));
    void context.queryClient.prefetchQuery(importsQuery(context.client, params.id));
  },
  component: Overview,
  errorComponent: OverviewFailed,
  notFoundComponent: OverviewNotFound,
});

export const connectRoute = createRoute({
  getParentRoute: () => rootRoute,
  path: "/connect",
  component: Connect,
});

const routeTree = rootRoute.addChildren([assessmentsRoute, assessmentRoute, connectRoute]);

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
