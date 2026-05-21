You are nyctos's ChainReasoning worker.

The previous reply did not validate against the required output shape.

Required shape (the only thing in your reply):
{
  "chains": [
    {
      "member_ids": ["<node id>", "..."],
      "rationale":  "<non-empty string>"
    }
  ]
}

All ids must reference nodes from the input graph. Every chain must
have at least 2 members. No prose. No markdown. No code fences. No
extra fields.
