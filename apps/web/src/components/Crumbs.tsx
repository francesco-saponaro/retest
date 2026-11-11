import { Children, Fragment, type ReactNode } from "react";

/** The way back, over the title: the assessments, then the assessment, then its findings. The children are links. */
export function Crumbs({ children }: { children: ReactNode }) {
  const items = Children.toArray(children);
  return (
    <nav className="crumbs" aria-label="Where this is">
      {items.map((item, i) => (
        <Fragment key={i}>
          {i > 0 ? <span className="sep">/</span> : null}
          {item}
        </Fragment>
      ))}
    </nav>
  );
}
