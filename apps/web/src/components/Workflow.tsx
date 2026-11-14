import { PHASES, PHASE_DETAILS, RETEST_OUTCOMES, isPhaseAfter, phaseChangeProblem, phaseNumber, retestProblem, statusChangeProblem, type Phase, type RetestOutcome } from "@retest/schema";
import { useId, useState, type FormEvent } from "react";
import type { FindingDetail, PhaseChange, RetestInput, StatusChange } from "../api/client.js";
import { messageOf, nextStep } from "../lib/format.js";

export interface WorkflowActions {
  phase: (change: PhaseChange) => Promise<unknown>;
  status: (change: StatusChange) => Promise<unknown>;
  retest: (input: RetestInput) => Promise<unknown>;
}

type Open = "none" | "back" | "false-positive" | "accepted-risk" | "reopen";

const RETEST_WORDS: Record<RetestOutcome, string> = { pending: "Pending", fixed: "Fixed", "partially-fixed": "Partially fixed", "not-fixed": "Not fixed" };

/**
 * Where the finding stands and what can be done to it next. The trail is the roadmap's six phases
 * with this finding's own marked; the primary action is the next phase, and when a rule refuses it
 * the button is disabled with the rule's own sentence under it, the same sentence the API answers.
 * Everything else (moving back, a false positive, an accepted risk, reopening) asks for its reason
 * in a small form, and the retest has its own form once the finding is in remediation.
 */
export function Workflow({ f, act }: { f: FindingDetail; act: WorkflowActions }) {
  const [open, setOpen] = useState<Open>("none");
  const [reason, setReason] = useState("");
  const [back, setBack] = useState<Phase | "">("");
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const reasonId = useId();

  const next = nextStep(f.phase);
  const nextProblem = next ? phaseChangeProblem(f, next.phase) : null;
  const isOpen = f.status === "open";
  const earlier = PHASES.filter((p) => isPhaseAfter(f.phase, p));
  const acceptProblem = statusChangeProblem(f, "accepted-risk", "x");

  const run = async (fn: () => Promise<unknown>) => {
    setBusy(true);
    setProblem(null);
    try {
      await fn();
      setOpen("none");
      setReason("");
      setBack("");
    } catch (e) {
      setProblem(messageOf(e));
    } finally {
      setBusy(false);
    }
  };

  const toggle = (what: Open) => {
    setProblem(null);
    setReason("");
    setOpen(open === what ? "none" : what);
  };

  const forward = (e: FormEvent) => {
    e.preventDefault();
    if (!next) return;
    void run(() => act.phase(reason.trim() ? { phase: next.phase, reason: reason.trim() } : { phase: next.phase }));
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const why = reason.trim();
    switch (open) {
      case "back":
        if (!back) return setProblem("choose the phase to go back to");
        return void run(() => act.phase(why ? { phase: back, reason: why } : { phase: back }));
      case "false-positive":
        return void run(() => act.status(why ? { status: "false-positive", reason: why } : { status: "false-positive" }));
      case "accepted-risk":
        return void run(() => act.status(why ? { status: "accepted-risk", reason: why } : { status: "accepted-risk" }));
      case "reopen":
        return void run(() => act.status(why ? { status: "open", reason: why } : { status: "open" }));
      default:
        return;
    }
  };

  const FORM_TITLES: Record<Exclude<Open, "none">, { title: string; button: string }> = {
    back: { title: "Move back", button: "Move back" },
    "false-positive": { title: "Mark as a false positive", button: "Confirm the false positive" },
    "accepted-risk": { title: "Accept the risk", button: "Accept the risk" },
    reopen: { title: "Reopen", button: "Reopen the finding" },
  };

  return (
    <div className="panel track">
      <ol className="trail" aria-label="The six phases">
        {PHASES.map((p) => {
          const now = p === f.phase;
          const done = phaseNumber(p) < phaseNumber(f.phase);
          return (
            <li key={p} className={`step${done ? " done" : ""}`} aria-current={now ? "step" : undefined}>
              <span className="label">{PHASE_DETAILS[p].label}</span>
              <span className="what">{now ? PHASE_DETAILS[p].activity : done ? "Passed" : ""}</span>
            </li>
          );
        })}
      </ol>

      <div className="moves">
        {isOpen && next && open === "none" ? (
          <form className="move-next" onSubmit={forward} aria-label={next.label}>
            <div className="field grow">
              <label htmlFor={`${reasonId}-why`}>Why</label>
              <input id={`${reasonId}-why`} className="input" value={reason} onChange={(e) => setReason(e.target.value)} placeholder="One line on what was done, kept in the history" disabled={nextProblem !== null} />
            </div>
            <button type="submit" className="btn primary" disabled={busy || nextProblem !== null}>
              {next.label}
            </button>
            {nextProblem ? (
              <p className="hint wide" style={{ color: "var(--warning)" }}>
                Not yet: {nextProblem}.
              </p>
            ) : null}
          </form>
        ) : null}
        <div className="move-set" role="group" aria-label="Set the finding aside or take it back">
          {isOpen && earlier.length > 0 ? (
            <button type="button" className="btn text" aria-expanded={open === "back"} onClick={() => toggle("back")}>
              Move back
            </button>
          ) : null}
          {isOpen ? (
            <button type="button" className="btn text" aria-expanded={open === "false-positive"} onClick={() => toggle("false-positive")}>
              Mark as a false positive
            </button>
          ) : null}
          {isOpen && acceptProblem === null ? (
            <button type="button" className="btn text" aria-expanded={open === "accepted-risk"} onClick={() => toggle("accepted-risk")}>
              Accept the risk
            </button>
          ) : null}
          {!isOpen ? (
            <button type="button" className="btn" aria-expanded={open === "reopen"} onClick={() => toggle("reopen")}>
              Reopen
            </button>
          ) : null}
        </div>
        {problem && open === "none" ? <p className="hint wide" style={{ color: "var(--negative)" }}>Not done: {problem}.</p> : null}
      </div>

      {open !== "none" ? (
        <form className="move-form" onSubmit={submit} aria-label={FORM_TITLES[open].title}>
          <h3>{FORM_TITLES[open].title}</h3>
          {open === "back" ? (
            <div className="field">
              <label htmlFor={`${reasonId}-to`}>To</label>
              <select id={`${reasonId}-to`} className="select" value={back} onChange={(e) => setBack(e.target.value as Phase)}>
                <option value="">Choose a phase</option>
                {earlier.map((p) => (
                  <option key={p} value={p}>
                    {PHASE_DETAILS[p].label}
                  </option>
                ))}
              </select>
            </div>
          ) : null}
          <div className="field">
            <label htmlFor={`${reasonId}-reason`}>Why</label>
            <textarea id={`${reasonId}-reason`} className="input area" rows={3} value={reason} onChange={(e) => setReason(e.target.value)} placeholder={open === "false-positive" ? "What was checked, and why the tool was wrong" : "Kept in the history"} />
            <div className="hint">{open === "accepted-risk" ? "Who accepts it, and until when or under which condition." : open === "false-positive" ? "The reason stays on the finding and in the history." : "The reason stays in the history."}</div>
          </div>
          <div className="actions">
            <button type="submit" className="btn primary" disabled={busy}>
              {FORM_TITLES[open].button}
            </button>
            <button type="button" className="btn text" onClick={() => toggle(open)}>
              Cancel
            </button>
            {problem ? <span style={{ color: "var(--negative)" }}>Not done: {problem}.</span> : null}
          </div>
        </form>
      ) : null}

      {isOpen && f.phase === "remediation" ? <RetestForm f={f} record={act.retest} /> : null}
    </div>
  );
}

/** The seventh field, written: what the checks showed after the fix. "Fixed" closes the finding. */
function RetestForm({ f, record }: { f: FindingDetail; record: (input: RetestInput) => Promise<unknown> }) {
  const [outcome, setOutcome] = useState<RetestOutcome | "">("");
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState(false);
  const [problem, setProblem] = useState<string | null>(null);
  const id = useId();
  const blocked = outcome ? retestProblem(f, outcome) : null;

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!outcome) return setProblem("choose what the retest found");
    if (!notes.trim()) return setProblem("say what the checks showed");
    setBusy(true);
    setProblem(null);
    try {
      await record({ outcome, notes: notes.trim() });
      setOutcome("");
      setNotes("");
    } catch (err) {
      setProblem(messageOf(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <form className="move-form retest" onSubmit={(e) => void submit(e)} aria-label="Record the retest">
      <h3>Record the retest</h3>
      <p className="muted">
        {f.retest && f.retest.outcome !== "pending" ? `The last retest found it ${RETEST_WORDS[f.retest.outcome].toLowerCase()}. ` : ""}
        The owner has fixed, or says so; test the same thing again, the same way, and write down what the checks showed. Fixed closes the finding.
      </p>
      <fieldset className="metric">
        <legend>Outcome</legend>
        <div className="choices">
          {RETEST_OUTCOMES.filter((o) => o !== "pending").map((o) => (
            <label key={o} className={outcome === o ? "choice on" : "choice"}>
              <input type="radio" name={`${id}-outcome`} value={o} checked={outcome === o} onChange={() => setOutcome(o)} />
              {RETEST_WORDS[o]}
            </label>
          ))}
        </div>
      </fieldset>
      <div className="field">
        <label htmlFor={`${id}-notes`}>What the checks showed</label>
        <textarea id={`${id}-notes`} className="input area" rows={3} value={notes} onChange={(e) => setNotes(e.target.value)} placeholder="The request made again, and what came back" />
      </div>
      <div className="actions">
        <button type="submit" className="btn primary" disabled={busy || blocked !== null}>
          Record the retest
        </button>
        {blocked ? <span style={{ color: "var(--warning)" }}>{blocked}.</span> : null}
        {problem ? <span style={{ color: "var(--negative)" }}>Not recorded: {problem}.</span> : null}
      </div>
    </form>
  );
}
