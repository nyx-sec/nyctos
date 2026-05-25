export interface GraphChainMember {
  id: string;
  graph_kind?: string | null;
  label?: string | null;
  ref_id?: string | null;
  repo?: string | null;
  path?: string | null;
  line?: number | null;
  cap?: string | null;
  rule?: string | null;
  severity?: string | null;
  routes?: string[];
  roles?: string[];
  objects?: string[];
  evidence_refs?: string[];
}

export interface GraphEdgeProvenance {
  from: string;
  to: string;
  kind: string;
  edge_id?: string | null;
  evidence_ref?: string | null;
  source?: string | null;
  cross_repo?: boolean;
}

export interface GraphChainEvidence {
  schema_version?: number;
  graph_backed?: boolean;
  member_ids?: string[];
  members?: GraphChainMember[];
  edge_provenance?: GraphEdgeProvenance[];
  model_edge_provenance?: string[];
  prerequisites?: string[];
  evidence?: string[];
  blast_radius?: string[];
  confidence?: number;
  missing_verification_steps?: string[];
}

export function parseChainEvidence(raw: string | null): GraphChainEvidence | null {
  if (!raw) return null;
  try {
    const parsed = JSON.parse(raw) as GraphChainEvidence;
    if (!parsed || typeof parsed !== "object") return null;
    return parsed;
  } catch {
    return null;
  }
}
