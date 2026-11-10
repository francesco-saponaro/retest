import { queryOptions } from "@tanstack/react-query";
import type { ApiClient } from "./api/client.js";

/** Every read the screens make, as query definitions, so a loader and a component ask for the same thing. */
export const assessmentsQuery = (client: ApiClient) => queryOptions({ queryKey: ["assessments"], queryFn: () => client.listAssessments() });

export const assessmentQuery = (client: ApiClient, id: string) => queryOptions({ queryKey: ["assessments", id], queryFn: () => client.getAssessment(id) });

export const assetsQuery = (client: ApiClient, id: string) => queryOptions({ queryKey: ["assessments", id, "assets"], queryFn: () => client.listAssets(id) });

export const importsQuery = (client: ApiClient, id: string) => queryOptions({ queryKey: ["assessments", id, "imports"], queryFn: () => client.listImports(id) });

export const auditQuery = (client: ApiClient, id: string) => queryOptions({ queryKey: ["assessments", id, "audit"], queryFn: () => client.listAudit(id) });
