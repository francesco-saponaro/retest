import { z } from "zod";

export const ASSET_KINDS = [
  "host",
  "service",
  "web-app",
  "api",
  "repository",
  "container-image",
  "cloud-account",
  "cloud-resource",
] as const;

export const AssetKindSchema = z.enum(ASSET_KINDS);
export type AssetKind = z.infer<typeof AssetKindSchema>;

export const PortSchema = z.number().int().min(1).max(65535);

/**
 * A thing that was tested. Findings point at an asset; the asset says what and where.
 * A host has a host name or address; a service adds a port; a web app or an API has a URL;
 * a repository, image or cloud resource is named by its identifier.
 */
export const AssetSchema = z
  .object({
    id: z.string().min(1),
    assessmentId: z.string().min(1),
    kind: AssetKindSchema,
    /** What a person calls it: "Juice Shop", "127.0.0.1", "http on 3000", "juice-shop:v17". */
    name: z.string().min(1).max(200),
    host: z.string().min(1).optional(),
    port: PortSchema.optional(),
    url: z.url().optional(),
    /** Out-of-scope assets can be recorded so that nobody tests them by mistake. */
    inScope: z.boolean().default(true),
    tags: z.array(z.string().min(1)).default([]),
  })
  .refine((a) => (a.kind === "web-app" || a.kind === "api" ? a.url !== undefined : true), {
    message: "a web app or an API needs a url",
    path: ["url"],
  });

export type Asset = z.infer<typeof AssetSchema>;
export type AssetInput = z.input<typeof AssetSchema>;

/** One line for a table row. */
export function assetLabel(asset: Asset): string {
  if (asset.url) return `${asset.name} (${asset.url})`;
  if (asset.host && asset.port !== undefined) return `${asset.host}:${asset.port} (${asset.name})`;
  return asset.name;
}
