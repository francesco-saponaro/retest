import { CvssError, SEVERITY_LABELS, formatVector, parseVector, scoreVector, type CvssVector, type Finding, type Risk } from "@retest/schema";
import { useState } from "react";
import { BASE_METRICS, claimsAgainst, riskFromVector, startingVector, withMetric } from "../lib/cvss.js";
import { messageOf } from "../lib/format.js";

/**
 * The eight base metrics as eight rows of choices, the vector they make, and the score the schema
 * computes for it, set against what each tool claimed. The vector can also be pasted. Storing it
 * puts the score and the severity it gives on the finding, through the same validation the API
 * runs: a severity that does not match its score is refused.
 */
export function CvssCalculator({ f, store }: { f: Pick<Finding, "risk" | "sources">; store: (risk: Risk) => Promise<unknown> }) {
  const [text, setText] = useState(() => startingVector(f));
  const [vector, setVector] = useState<CvssVector>(() => parseVector(startingVector(f)));
  const [problem, setProblem] = useState<string | null>(null);
  const [stored, setStored] = useState<"idle" | "saving" | "done" | "failed">("idle");
  const [failure, setFailure] = useState("");

  const scores = scoreVector(vector);
  const claims = claimsAgainst(f, scores.vector);
  const isStored = f.risk.cvss?.vector === scores.vector;

  const choose = (key: (typeof BASE_METRICS)[number]["key"], code: string) => {
    const next = withMetric(vector, key, code);
    setVector(next);
    setText(formatVector(next));
    setProblem(null);
    setStored("idle");
  };

  const typed = (value: string) => {
    setText(value);
    setStored("idle");
    try {
      setVector(parseVector(value));
      setProblem(null);
    } catch (e) {
      setProblem(e instanceof CvssError ? e.message : messageOf(e));
    }
  };

  const save = async () => {
    setStored("saving");
    try {
      await store(riskFromVector(scores.vector));
      setStored("done");
    } catch (e) {
      setFailure(messageOf(e));
      setStored("failed");
    }
  };

  return (
    <div className="panel calc" role="region" aria-label="CVSS calculator">
      <div className="result">
        <div className="field">
          <label htmlFor="cvss-vector">Vector</label>
          <input id="cvss-vector" className="input" value={text} onChange={(e) => typed(e.target.value)} spellCheck={false} aria-invalid={problem ? true : undefined} aria-describedby={problem ? "cvss-problem" : undefined} />
          {problem ? (
            <div id="cvss-problem" className="hint" style={{ color: "var(--negative)" }}>
              Not a vector: {problem}.
            </div>
          ) : (
            <div className="hint">The score is the vector's; the severity is the score's. The temporal metrics E, RL and RC may be pasted too.</div>
          )}
        </div>
        <div className="score">
          <div className="label">Base score</div>
          <div className={`value num${scores.baseScore === 0 ? " zero" : ""}`}>{scores.baseScore.toFixed(1)}</div>
          <div className="word">{SEVERITY_LABELS[scores.severity]}</div>
          <div className="muted text-[13px]">
            Impact {scores.impactSubScore.toFixed(1)} · Exploitability {scores.exploitabilitySubScore.toFixed(1)}
            {scores.temporalScore !== scores.baseScore ? ` · Temporal ${scores.temporalScore.toFixed(1)}` : ""}
          </div>
        </div>
        {claims.length ? (
          <ul className="claims" aria-label="What the tools claimed">
            {claims.map((c) => (
              <li key={c.tool} className={c.agrees === false ? "differs" : undefined}>
                {c.tool}: {c.claim}
              </li>
            ))}
          </ul>
        ) : null}
        <div className="actions">
          {stored === "done" ? (
            <span className="muted">Stored as the finding's risk.</span>
          ) : isStored ? (
            <span className="muted">This is the finding's risk.</span>
          ) : (
            <button type="button" className="btn primary" disabled={stored === "saving" || problem !== null} onClick={() => void save()}>
              {stored === "saving" ? "Storing" : "Use as the finding's risk"}
            </button>
          )}
          {stored === "failed" ? <span style={{ color: "var(--negative)" }}>Not stored: {failure}.</span> : null}
        </div>
      </div>
      <div className="metrics">
        {BASE_METRICS.map((m) => (
          <fieldset key={m.key} className="metric">
            <legend>{m.label}</legend>
            <div className="choices">
              {m.values.map((v) => (
                <label key={v.code} className={vector[m.key] === v.code ? "choice on" : "choice"}>
                  <input type="radio" name={`cvss-${m.key}`} value={v.code} aria-label={`${m.label}: ${v.label}`} checked={vector[m.key] === v.code} onChange={() => choose(m.key, v.code)} />
                  {v.label}
                </label>
              ))}
            </div>
          </fieldset>
        ))}
      </div>
    </div>
  );
}
