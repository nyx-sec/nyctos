import { useMemo } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import {
  type ChainRecord,
  type FindingRecord,
  type NyxSignalRecord,
  useChain,
  useFinding,
  useRunSignals,
} from "@/api/client";
import { Badge } from "@/components/Badge";
import { Button } from "@/components/Button";
import { Card } from "@/components/Card";
import { EmptyState } from "@/components/EmptyState";
import { PageHeader, PageShell } from "@/components/Page";
import { Spinner } from "@/components/Spinner";
import { extractChainRationale } from "@/pages/Findings/FindingList";
import { shortChainId } from "./ChainList";
import { type GraphChainMember, parseChainEvidence } from "./chainEvidence";
import { parseMemberIds } from "./memberIds";

export function ChainDetail() {
  const { chainId = "", projectId } = useParams<{ chainId: string; projectId?: string }>();
  const navigate = useNavigate();
  const chainQuery = useChain(chainId);
  const chainListHref = projectId ? `/projects/${encodeURIComponent(projectId)}/chains` : "/chains";

  return (
    <PageShell className="findings-page">
      <PageHeader
        title={chainQuery.data ? `Chain ${shortChainId(chainQuery.data.id)}` : "Chain"}
        meta={chainQuery.data?.run_id ? `Run ${chainQuery.data.run_id}` : undefined}
        actions={
          <Button variant="ghost" size="sm" onClick={() => navigate(chainListHref)}>
            Back to chains
          </Button>
        }
      />

      {chainQuery.isPending && (
        <Card>
          <div className="findings-page__pending">
            <Spinner /> Loading chain…
          </div>
        </Card>
      )}

      {chainQuery.error && (
        <Card>
          <p className="findings-page__error" role="alert">
            Failed to load chain: {String(chainQuery.error)}
          </p>
        </Card>
      )}

      {chainQuery.data && <ChainBody chain={chainQuery.data} projectId={projectId} />}
    </PageShell>
  );
}

interface ChainBodyProps {
  chain: ChainRecord;
  projectId?: string;
}
function ChainBody({ chain, projectId }: ChainBodyProps) {
  const rationale = extractChainRationale(chain.rationale_blob);
  const members = parseMemberIds(chain.member_ids);
  const graphEvidence = parseChainEvidence(chain.evidence_blob);
  const graphMembers = graphEvidence?.members ?? [];
  const signalsQuery = useRunSignals(members.length > 0 ? chain.run_id : undefined);
  const signalsByMemberId = useMemo(
    () => indexSignalsByMemberId(signalsQuery.data ?? []),
    [signalsQuery.data],
  );

  return (
    <>
      <Card
        title="Rationale"
        subtitle={
          <>
            {chain.cross_repo ? (
              <Badge tone="accent">cross-repo</Badge>
            ) : (
              <Badge tone="neutral">single-repo</Badge>
            )}
            <span style={{ marginLeft: "0.5rem" }}>
              Run <code>{chain.run_id}</code>
            </span>
            {chain.prompt_version && (
              <span style={{ marginLeft: "0.5rem" }}>
                · <code>{chain.prompt_version}</code>
              </span>
            )}
            {typeof graphEvidence?.confidence === "number" && (
              <span style={{ marginLeft: "0.5rem" }}>· {graphEvidence.confidence}% confidence</span>
            )}
          </>
        }
      >
        {rationale ? (
          <p className="chain-detail__rationale">{rationale}</p>
        ) : (
          <p className="chain-detail__rationale chain-detail__rationale--empty">
            No rationale text recorded for this chain.
          </p>
        )}
      </Card>

      {graphEvidence && (
        <Card title="Graph Evidence">
          {graphMembers.length > 0 && (
            <ol className="chain-detail__graph-path">
              {graphMembers.map((member) => (
                <li key={member.id}>
                  <GraphMember member={member} />
                </li>
              ))}
            </ol>
          )}
          {(graphEvidence.edge_provenance?.length ?? 0) > 0 && (
            <ul className="chain-detail__evidence-list">
              {graphEvidence.edge_provenance?.map((edge, index) => (
                <li key={`${edge.from}-${edge.to}-${index}`}>
                  <code>{edge.kind}</code> {shortNode(edge.from)} → {shortNode(edge.to)}
                  {edge.evidence_ref ? (
                    <>
                      {" "}
                      via <code>{edge.evidence_ref}</code>
                    </>
                  ) : edge.edge_id ? (
                    <>
                      {" "}
                      via <code>{edge.edge_id}</code>
                    </>
                  ) : null}
                </li>
              ))}
            </ul>
          )}
          <EvidenceSection title="Prerequisites" values={graphEvidence.prerequisites} />
          <EvidenceSection title="Evidence" values={graphEvidence.evidence} />
          <EvidenceSection title="Blast radius" values={graphEvidence.blast_radius} />
          <EvidenceSection
            title="Missing verification"
            values={graphEvidence.missing_verification_steps}
          />
        </Card>
      )}

      <Card title={`Members (${members.length})`}>
        {members.length === 0 ? (
          <EmptyState title="No member findings" />
        ) : (
          <ul className="chain-detail__members">
            {members.map((id) => (
              <li key={id}>
                <MemberRow
                  memberId={id}
                  runId={chain.run_id}
                  projectId={projectId}
                  signal={signalsByMemberId.get(id)}
                  signalsPending={signalsQuery.isPending}
                />
              </li>
            ))}
          </ul>
        )}
      </Card>
    </>
  );
}

function GraphMember({ member }: { member: GraphChainMember }) {
  const tags = [member.graph_kind, member.severity].filter(Boolean).join(" · ");
  const context = [...(member.routes ?? []), ...(member.roles ?? []), ...(member.objects ?? [])]
    .filter(Boolean)
    .slice(0, 4);
  return (
    <div className="chain-detail__graph-member">
      <div>
        <span className="chain-detail__graph-title">
          {member.label || member.ref_id || member.id}
        </span>
        {tags && <span className="chain-detail__graph-tags">{tags}</span>}
      </div>
      <code>{member.ref_id || member.id}</code>
      {context.length > 0 && <p>{context.join(" · ")}</p>}
    </div>
  );
}

function EvidenceSection({ title, values }: { title: string; values?: string[] }) {
  if (!values || values.length === 0) return null;
  return (
    <div className="chain-detail__evidence-section">
      <h3>{title}</h3>
      <ul>
        {values.map((value) => (
          <li key={value}>{value}</li>
        ))}
      </ul>
    </div>
  );
}

function shortNode(id: string): string {
  return id.length > 16 ? `${id.slice(0, 16)}…` : id;
}

interface MemberRowProps {
  memberId: string;
  runId: string;
  projectId?: string;
  signal: NyxSignalRecord | undefined;
  signalsPending: boolean;
}

function MemberRow({ memberId, runId, projectId, signal, signalsPending }: MemberRowProps) {
  const finding = useFinding(memberId);
  const focusHref = findingFocusHref(runId, memberId, projectId);

  if (finding.data) {
    return <FindingMemberRow finding={finding.data} focusHref={focusHref} />;
  }

  if (signal) {
    return <SignalMemberRow signal={signal} memberId={memberId} />;
  }

  if (finding.isPending || signalsPending) {
    return (
      <span className="chain-detail__member chain-detail__member--pending">
        <Spinner /> {memberId}
      </span>
    );
  }
  return (
    <span className="chain-detail__member chain-detail__member--missing">
      <code>{memberId}</code> — linked record not found
    </span>
  );
}

function findingFocusHref(runId: string, memberId: string, projectId: string | undefined): string {
  const prefix = projectId ? `/projects/${encodeURIComponent(projectId)}` : "";
  return `${prefix}/findings?run_id=${encodeURIComponent(runId)}&focus=${encodeURIComponent(memberId)}`;
}

function FindingMemberRow({ finding, focusHref }: { finding: FindingRecord; focusHref: string }) {
  return (
    <Link className="chain-detail__member" to={focusHref}>
      <span className="chain-detail__member-cap">
        <Badge tone="accent">{finding.cap}</Badge>
      </span>
      <span className="chain-detail__member-repo">{finding.repo}</span>
      <span className="chain-detail__member-path">
        {finding.path}
        {finding.line !== null ? `:${finding.line}` : ""}
      </span>
      <span className="chain-detail__member-rule">{finding.rule}</span>
    </Link>
  );
}

function SignalMemberRow({ signal, memberId }: { signal: NyxSignalRecord; memberId: string }) {
  return (
    <span
      className="chain-detail__member chain-detail__member--signal"
      title={signal.message ?? memberId}
    >
      <span className="chain-detail__member-cap">
        <Badge tone="accent">{signal.cap}</Badge>
      </span>
      <span className="chain-detail__member-repo">{signal.repo}</span>
      <span className="chain-detail__member-path">
        {displaySignalPath(signal.path, signal.run_id)}
        {signal.line !== null ? `:${signal.line}` : ""}
      </span>
      <span className="chain-detail__member-rule">{signal.rule}</span>
    </span>
  );
}

export function indexSignalsByMemberId(signals: NyxSignalRecord[]): Map<string, NyxSignalRecord> {
  const index = new Map<string, NyxSignalRecord>();
  for (const signal of signals) {
    if (!index.has(signal.id)) {
      index.set(signal.id, signal);
    }
    const suffix = signal.id.slice(signal.id.lastIndexOf("-") + 1);
    if (suffix && !index.has(suffix)) {
      index.set(suffix, signal);
    }
  }
  return index;
}

export function displaySignalPath(path: string, runId: string): string {
  const marker = `/snapshots/${runId}/`;
  const idx = path.indexOf(marker);
  return idx === -1 ? path : path.slice(idx + marker.length);
}
