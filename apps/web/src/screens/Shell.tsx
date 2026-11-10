import { Link, useLocation } from "@tanstack/react-router";
import type { ReactNode } from "react";
import { rootRoute } from "../router.js";
import { hasToken } from "../token.js";

/** The product's mark: a test, and the retest drawn over it. */
export function Mark() {
  return (
    <svg viewBox="0 0 20 20" aria-hidden="true" focusable="false">
      <path d="M10 2.5a7.5 7.5 0 1 1-7.5 7.5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      <path d="M6.5 10.2l2.4 2.4L14 7.5" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/** A 48px bar on the ground over one centred column: the mark and the name, the destinations, and where the data comes from. */
export function Shell({ children }: { children: ReactNode }) {
  const { client } = rootRoute.useRouteContext();
  const path = useLocation({ select: (l) => l.pathname });
  const inAssessments = path === "/" || path.startsWith("/a/");
  return (
    <>
      <header className="bar">
        <div className="bar-inner">
          <Link to="/" className="mark" aria-label="Retest, assessments">
            <Mark />
            <span>Retest</span>
          </Link>
          <nav className="bar-links" aria-label="Main">
            <Link to="/" aria-current={inAssessments ? "page" : undefined}>
              Assessments
            </Link>
          </nav>
          <div className="bar-right">
            {client.mode === "demo" ? (
              <span>
                Demo<span className="long">: the lab, made in this tab</span>
              </span>
            ) : hasToken() ? (
              <Link to="/connect" className="crumb">
                Connected
              </Link>
            ) : (
              <Link to="/connect" className="btn">
                Connect
              </Link>
            )}
          </div>
        </div>
      </header>
      <main className="canvas">{children}</main>
    </>
  );
}
