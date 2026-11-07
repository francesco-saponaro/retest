import { XMLParser, XMLValidator } from "fast-xml-parser";

/** A parsed XML element: attributes as string fields, children as arrays, text under `#text`. */
export type XmlNode = { [key: string]: unknown; "#text"?: string };

const NAMED: Record<string, string> = { lt: "<", gt: ">", amp: "&", quot: '"', apos: "'" };

/** Decode the five XML entities and numeric references. Nmap writes newlines in attributes as `&#xa;`. */
export function decodeEntities(value: string): string {
  return value.replace(/&(#x[0-9a-fA-F]+|#[0-9]+|lt|gt|amp|quot|apos);/g, (whole, body: string) => {
    if (body.startsWith("#x")) return String.fromCodePoint(Number.parseInt(body.slice(2), 16));
    if (body.startsWith("#")) return String.fromCodePoint(Number.parseInt(body.slice(1), 10));
    return NAMED[body] ?? whole;
  });
}

/**
 * Parse an XML document into plain objects. Every element named in `arrays` is always a list,
 * so callers never have to check whether there was one child or several. Values stay strings;
 * entities are decoded here, once, on the way out.
 */
export function parseXml(xml: string, arrays: readonly string[]): XmlNode | undefined {
  if (XMLValidator.validate(xml) !== true) return undefined;
  const parser = new XMLParser({
    ignoreAttributes: false,
    attributeNamePrefix: "",
    parseTagValue: false,
    parseAttributeValue: false,
    trimValues: false,
    alwaysCreateTextNode: true,
    ignoreDeclaration: true,
    ignorePiTags: true,
    processEntities: false,
    isArray: (name) => arrays.includes(name),
  });
  return decodeDeep(parser.parse(xml) as XmlNode) as XmlNode;
}

function decodeDeep(value: unknown): unknown {
  if (typeof value === "string") return decodeEntities(value);
  if (Array.isArray(value)) return value.map(decodeDeep);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value)) out[k] = decodeDeep(v);
    return out;
  }
  return value;
}

/** A string attribute, or undefined when it is missing. */
export function attr(node: XmlNode | undefined, name: string): string | undefined {
  const v = node?.[name];
  return typeof v === "string" ? v : undefined;
}

/** An attribute that must be a number. */
export function numAttr(node: XmlNode | undefined, name: string): number | undefined {
  const v = attr(node, name);
  if (v === undefined) return undefined;
  const n = Number(v);
  return Number.isFinite(n) ? n : undefined;
}

/** A child element list (empty when absent). */
export function children(node: XmlNode | undefined, name: string): XmlNode[] {
  const v = node?.[name];
  if (Array.isArray(v)) return v as XmlNode[];
  if (v && typeof v === "object") return [v as XmlNode];
  return [];
}

/** The single child element, when there is one. */
export function child(node: XmlNode | undefined, name: string): XmlNode | undefined {
  return children(node, name)[0];
}

/** The text of a node (empty string when it has none). */
export function text(node: XmlNode | undefined): string {
  return node?.["#text"] ?? "";
}
