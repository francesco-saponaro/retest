/** Small text helpers shared by the parsers. */

const NAMED_ENTITIES: Record<string, string> = {
  amp: "&",
  lt: "<",
  gt: ">",
  quot: '"',
  apos: "'",
  nbsp: " ",
};

/** Decode the HTML entities a report can carry: named, decimal and hex. */
export function decodeEntities(value: string): string {
  return value.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (whole, body: string) => {
    if (body[0] === "#") {
      const code = body[1]?.toLowerCase() === "x" ? parseInt(body.slice(2), 16) : parseInt(body.slice(1), 10);
      return Number.isFinite(code) ? String.fromCodePoint(code) : whole;
    }
    return NAMED_ENTITIES[body.toLowerCase()] ?? whole;
  });
}

/**
 * Plain text out of the HTML snippets ZAP writes in its descriptions: each `<p>` becomes a
 * line, every other tag goes, entities are decoded, whitespace is tidied.
 */
export function stripHtml(html: string): string {
  const lines = html
    .replace(/<br\s*\/?>/gi, "\n")
    .replace(/<\/p>\s*<p[^>]*>/gi, "\n")
    .replace(/<[^>]+>/g, "")
    .split("\n")
    .map((line) => decodeEntities(line).replace(/\s+/g, " ").trim())
    .filter((line) => line.length > 0);
  return lines.join("\n");
}

/** Cut a string to a length, with an ellipsis when something was cut. */
export function cut(value: string, max: number): string {
  return value.length <= max ? value : `${value.slice(0, max - 1)}…`;
}
