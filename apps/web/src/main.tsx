import { QueryClient } from "@tanstack/react-query";
import { RouterProvider } from "@tanstack/react-router";
import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import type { ApiClient } from "./api/client.js";
import { httpClient } from "./api/http.js";
import "./app.css";
import { createAppRouter } from "./router.js";
import { getToken } from "./token.js";

/**
 * `VITE_DEMO=1` builds the static demo: the API's services run in the browser against PostgreSQL in
 * WebAssembly, seeded from the bundled fixtures. Otherwise the app talks to `apps/api`, through the
 * dev server's `/api` proxy by default or at `VITE_API_URL`.
 */
async function client(): Promise<ApiClient> {
  if (import.meta.env.VITE_DEMO === "1") {
    const { demoClient } = await import("./api/demo.js");
    return demoClient();
  }
  return httpClient({ baseUrl: import.meta.env.VITE_API_URL ?? "/api", token: getToken });
}

const root = createRoot(document.getElementById("root")!);
root.render(
  <StrictMode>
    <main className="canvas">
      <div className="title-row">
        <div>
          <h1>Retest</h1>
          <p className="sub">{import.meta.env.VITE_DEMO === "1" ? "Making the lab in this tab: a database, then six scanner files." : "Loading."}</p>
        </div>
      </div>
    </main>
  </StrictMode>,
);

const queryClient = new QueryClient({ defaultOptions: { queries: { staleTime: 30_000, retry: 1 } } });
const api = await client();
root.render(
  <StrictMode>
    <RouterProvider router={createAppRouter({ client: api, queryClient })} />
  </StrictMode>,
);
