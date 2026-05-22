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
import { Spinner } from "@/components/Spinner";
import { extractChainRationale } from "@/pages/Findings/FindingList";
import { shortChainId } from "./ChainList";
import { parseMemberIds } from "./memberIds";

export function ChainDetail() {
  const { chainId = "" } = useParams<{ chainId: string }>();
  const navigate = useNavigate();
  const chainQuery = useChain(chainId);

  return (
    <div className="findings-page">
      <div className="page-toolbar">
        <p className="page-toolbar__meta">
          {chainQuery.data ? `Chain ${shortChainId(chainQuery.data.id)}` : "Chain"}
        </p>
        <Button variant="ghost" size="sm" onClick={() => navigate("/chains")}>
          ← Back to chains
        </Button>
      </div>

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

      {chainQuery.data && <ChainBody chain={chainQuery.data} />}
    </div>
  );
}

interface ChainBodyProps {
  chain: ChainRecord;
}
function ChainBody({ chain }: ChainBodyProps) {
  const rationale = extractChainRationale(chain.rationale_blob);
  const members = parseMemberIds(chain.member_ids);
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

      <Card
        title={`Members (${members.length})`}
        subtitle={
          members.length > 0
            ? "Findings and signals linked by this chain. Click legacy findings to open them."
            : undefined
        }
      >
        {members.length === 0 ? (
          <EmptyState
            title="No member findings"
            body="This chain row has no member ids on the wire — the rationale stands alone."
          />
        ) : (
          <ul className="chain-detail__members">
            {members.map((id) => (
              <li key={id}>
                <MemberRow
                  memberId={id}
                  runId={chain.run_id}
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

interface MemberRowProps {
  memberId: string;
  runId: string;
  signal: NyxSignalRecord | undefined;
  signalsPending: boolean;
}

function MemberRow({ memberId, runId, signal, signalsPending }: MemberRowProps) {
  const finding = useFinding(memberId);
  const focusHref = `/findings?run_id=${encodeURIComponent(runId)}&focus=${encodeURIComponent(memberId)}`;

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
