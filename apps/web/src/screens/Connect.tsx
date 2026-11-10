import { useNavigate, useRouter } from "@tanstack/react-router";
import { useState, type FormEvent } from "react";
import { clearToken, getToken, setToken } from "../token.js";
import { connectRoute } from "../router.js";

/**
 * The token for the API. There is no login: a token is minted on the command line by whoever holds
 * the API's secret, and pasted here. It stays in this tab's session storage and nowhere else.
 */
export function Connect() {
  const { client } = connectRoute.useRouteContext();
  const navigate = useNavigate();
  const router = useRouter();
  const [token, setValue] = useState(getToken() ?? "");

  if (client.mode === "demo") {
    return (
      <>
        <div className="title-row">
          <div>
            <h1>Connect</h1>
            <p className="sub">The demo needs no token: its data is made in this tab from the lab's scanner output and goes away with the tab.</p>
          </div>
        </div>
        <div className="panel max-w-[640px] p-5 grid gap-3">
          <h2 className="text-[16px] font-medium">Running it against the API instead</h2>
          <p>
            Start the API with <code>pnpm -C apps/api dev</code> and a <code>RETEST_JWT_SECRET</code> of at least 32 characters, seed the lab with <code>pnpm -C apps/api seed</code>, mint a token with{" "}
            <code>pnpm -C apps/api token &lt;user&gt;</code>, then start the web app with <code>pnpm -C apps/web dev</code> and paste the token on this screen.
          </p>
        </div>
      </>
    );
  }

  const save = async (e: FormEvent) => {
    e.preventDefault();
    const t = token.trim();
    if (t) setToken(t);
    else clearToken();
    await router.invalidate();
    await navigate({ to: "/" });
  };

  return (
    <>
      <div className="title-row">
        <div>
          <h1>Connect</h1>
          <p className="sub">Paste a token for the API. It is kept for this tab only and goes when the tab closes.</p>
        </div>
      </div>
      <form className="panel max-w-[560px] p-5 grid gap-4" onSubmit={(e) => void save(e)}>
        <div className="field">
          <label htmlFor="token">API token</label>
          <input id="token" className="input" type="password" autoComplete="off" value={token} onChange={(e) => setValue(e.target.value)} aria-describedby="token-hint" />
          <p id="token-hint" className="hint">
            Minted on the machine that runs the API with <code>pnpm -C apps/api token &lt;user&gt;</code>; it is good for 24 hours.
          </p>
        </div>
        <div className="flex gap-3">
          <button type="submit" className="btn primary">
            Save
          </button>
          {getToken() ? (
            <button type="button" className="btn" onClick={() => { clearToken(); setValue(""); void router.invalidate(); }}>
              Forget
            </button>
          ) : null}
        </div>
      </form>
    </>
  );
}
