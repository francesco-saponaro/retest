import { PHASES, PHASE_DETAILS, type Phase, type Scope } from "@retest/schema";
import type { Totals } from "../api/client.js";

/** "3 of 6 · Vulnerability assessment". */
export function phaseLine(phase: Phase): string {
  return `${PHASE_DETAILS[phase].number} of ${PHASES.length} · ${PHASE_DETAILS[phase].label}`;
}

const DAY = 24 * 60 * 60 * 1000;

/** "today", "yesterday", "3 days ago" up to a week, then the date. Days are counted on the calendar, in UTC. */
export function relativeDay(iso: string, now = new Date()): string {
  const then = new Date(iso);
  const days = Math.floor(Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate()) / DAY) - Math.floor(Date.UTC(then.getUTCFullYear(), then.getUTCMonth(), then.getUTCDate()) / DAY);
  if (days <= 0) return "today";
  if (days === 1) return "yesterday";
  if (days <= 7) return `${days} days ago`;
  return isoDate(iso);
}

/** "today 19:52", "yesterday 18:00", then the date; the clock in the reader's own zone. */
export function relativeTime(iso: string, now = new Date()): string {
  const day = relativeDay(iso, now);
  if (day !== "today" && day !== "yesterday") return day;
  const d = new Date(iso);
  return `${day} ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
}

/** The date part of an ISO timestamp, in UTC. */
export function isoDate(iso: string): string {
  return iso.slice(0, 10);
}

/** The findings that reached validation or a later phase: the ones somebody, not a scanner, has looked at. */
export function verifiedCount(totals: Totals): number {
  return totals.byPhase.validation + totals.byPhase.risk + totals.byPhase.remediation;
}

/** "5 targets, no exclusions · authorised by francesco on 2026-11-10". */
export function scopeLine(scope: Scope): string {
  const exclusions = scope.exclusions.length === 0 ? "no exclusions" : count(scope.exclusions.length, "exclusion");
  const when = scope.authorizedAt ? ` on ${isoDate(scope.authorizedAt)}` : "";
  return `${count(scope.targets.length, "target")}, ${exclusions} · authorised by ${scope.authorizedBy}${when}`;
}

/** "1 finding", "37 findings", "8 entries". */
export function count(n: number, noun: string): string {
  if (n === 1) return `1 ${noun}`;
  const plural = /[^aeiou]y$/.test(noun) ? `${noun.slice(0, -1)}ies` : `${noun}s`;
  return `${n} ${plural}`;
}

/** The one line under an assessment's title: how much of it is still only what a scanner said. */
export function findingLine(totals: Totals): string {
  const { findings, assets } = totals;
  if (findings === 0) return assets === 0 ? "No findings and no assets yet: nothing has been imported." : `No findings yet on ${count(assets, "asset")}: nothing has been imported.`;
  const verified = verifiedCount(totals);
  const head = `${count(findings, "finding")} on ${count(assets, "asset")}`;
  if (verified === 0) return `${head}, and all ${findings} are still what a scanner said: none has reached validation.`;
  if (verified === findings) return `${head}; all of it verified.`;
  return `${head}; ${verified} verified, ${findings - verified} still what a scanner said.`;
}

/** What went wrong, in one line, whatever was thrown. */
export function messageOf(error: unknown): string {
  if (error instanceof Error) return error.message;
  return typeof error === "string" ? error : "unknown error";
}
