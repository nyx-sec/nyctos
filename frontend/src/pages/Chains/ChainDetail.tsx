import { Link, useNavigate, useParams } from "react-router-dom";
import { Badge } from "@/components/Badge";
import { Button } from "@/components/Button";
import { Card } from "@/components/Card";
import { EmptyState } from "@/components/EmptyState";
import { Spinner } from "@/components/Spinner";
import {
  useChain,
  useFinding,
} from "@/api/client";
import { extractChainRationale } from "@/pages/Findings/FindingList";
import { parseMemberIds } from "./memberIds";
import { shortChainId } from "./ChainList";

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
  chain: import("@/api/client").ChainRecord;
}

function ChainBody({ chain }: ChainBodyProps) {
  const rationale = extractChainRationale(chain.rationale_blob);
  const members = parseMemberIds(chain.member_ids);

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
            ? "Findings linked by this chain. Click to open the finding."
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
                <MemberRow memberId={id} runId={chain.run_id} />
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
}

function MemberRow({ memberId, runId }: MemberRowProps) {
  const finding = useFinding(memberId);
  const focusHref = `/findings?run_id=${encodeURIComponent(runId)}&focus=${encodeURIComponent(memberId)}`;

  if (finding.isPending) {
    return (
      <span className="chain-detail__member chain-detail__member--pending">
        <Spinner /> {memberId}
      </span>
    );
  }
  if (finding.error || !finding.data) {
    return (
      <span className="chain-detail__member chain-detail__member--missing">
        <code>{memberId}</code> — finding not found
      </span>
    );
  }

  const f = finding.data;
  return (
    <Link className="chain-detail__member" to={focusHref}>
      <span className="chain-detail__member-cap">
        <Badge tone="accent">{f.cap}</Badge>
      </span>
      <span className="chain-detail__member-repo">{f.repo}</span>
      <span className="chain-detail__member-path">
        {f.path}
        {f.line !== null ? `:${f.line}` : ""}
      </span>
      <span className="chain-detail__member-rule">{f.rule}</span>
    </Link>
  );
}
