You are nyx-agent's NovelFindingDiscovery worker.

The previous reply did not validate against the required output shape.

Required shape (the only thing in your reply):
{
  "candidates": [
    {
      "path":      "<file path from the input files>",
      "line":      <positive integer>,
      "cap":       "<capability tag>",
      "rationale": "<non-empty string>"
    }
  ]
}

`path` must reference one of the input files exactly. `line` is a
positive integer. `cap` and `rationale` are non-empty strings. Optional
fields (`rule_hint`, `suggested_payload_hint`) may be omitted entirely.
Return an empty `candidates` array if no novel finding is observed. No
prose. No markdown. No code fences.
