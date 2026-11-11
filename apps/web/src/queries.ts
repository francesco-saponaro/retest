import { queryOptions } from "@tanstack/react-query";
import type { ApiClient, FindingFilter } from "./api/client.js";

/** Every read the screens make, as query definitions, so a loader and a component ask for the same thing. */
export const assessmentsQuery = (client: ApiClient) => queryOptions({ queryKey: ["assessments"], queryFn: () => client.listAssessments() });

export const assessmentQuery = (client: ApiClient, id: string) => queryOptions({ queryKey: ["assessments", id], queryFn: () => client.getAssessment(id) });

export const assetsQuery = (client: ApiClient, id: string) => queryOptions({ queryKey: ["assessments", id, "assets"], queryFn: () => client.listAssets(id) });

export const importsQuery = (client: ApiClient, id: string) => queryOptions({ queryKey: ["assessments", id, "imports"], queryFn: () => client.listImports(id) });

export const auditQuery = (client: ApiClient, id: string) => queryOptions({ queryKey: ["assessments", id, "audit"], queryFn: () => client.listAudit(id) });

/** One page of findings for one set of filters; the filters are part of the key, so each combination is cached on its own. */
export const findingsQuery = (client: ApiClient, id: string, filter: FindingFilter) =>
  queryOptions({ queryKey: ["assessments", id, "findings", filter], queryFn: () => client.listFindings(id, filter) });

export const findingQuery = (client: ApiClient, fid: string) => queryOptions({ queryKey: ["findings", fid], queryFn: () => client.getFinding(fid) });
