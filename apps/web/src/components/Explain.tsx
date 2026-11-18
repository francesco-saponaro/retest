import type { ReactNode } from "react";

/**
 * Plain words under a section title: what this part of the screen is, for someone who has never run
 * a security assessment. `terms` adds a fold-out list that explains each column or word the
 * section uses, so the screen stays quiet for someone who already knows them.
 */
export function Explain({ children, terms, label = "What the columns mean" }: { children: ReactNode; terms?: [string, ReactNode][]; label?: string }) {
  return (
    <div className="explain">
      <p>{children}</p>
      {terms ? (
        <details>
          <summary>{label}</summary>
          <dl>
            {terms.map(([term, meaning]) => (
              <div key={term}>
                <dt>{term}</dt>
                <dd>{meaning}</dd>
              </div>
            ))}
          </dl>
        </details>
      ) : null}
    </div>
  );
}
