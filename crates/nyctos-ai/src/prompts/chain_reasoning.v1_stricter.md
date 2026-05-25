You are nyctos's ChainReasoning worker.

The previous reply did not validate against the required output shape.

Required shape (the only thing in your reply):
{
  "chains": [
    {
      "member_ids": ["<node id>", "..."],
      "rationale":  "<non-empty string>",
      "prerequisites": ["<string>"],
      "evidence": ["<string>"],
      "blast_radius": ["<string>"],
      "confidence": 0,
      "missing_verification_steps": ["<string>"],
      "edge_provenance": ["<edge id or evidence ref>"]
    }
  ]
}

All ids must reference nodes from the input graph. Every adjacent pair
in `member_ids` must be connected by an input edge. Every chain must
have at least 2 members. `confidence` must be an integer from 0 to 100.
No prose. No markdown. No code fences. No extra fields.
