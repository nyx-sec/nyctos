## Summary

<!-- What changed, and why? Keep it short. -->

## Security / Safety Notes

<!-- Call out API, sandbox, AI, state-dir, live-probe, auth, or generated DTO boundary changes. Write "None" if not applicable. -->

## Verification

<!-- List the checks you ran. Include failures or skipped checks with the reason. -->

## Checklist

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- [ ] `cargo check --workspace --all-features --tests`
- [ ] `cargo nextest run --workspace --all-features`
- [ ] `npm --prefix frontend run format:check`
- [ ] `npm --prefix frontend run lint`
- [ ] `npm --prefix frontend run typecheck`
- [ ] `npm --prefix frontend test`
- [ ] `npm --prefix frontend run build`
- [ ] Generated TS bindings are fresh if shared DTOs changed
- [ ] SQLx metadata is fresh if migrations or checked queries changed
- [ ] Docs updated for behavior, config, CLI, API, setup, or safety changes
- [ ] UI changes include screenshot or recording when helpful

## Reviewer Notes

<!-- Anything reviewers should look at first, tradeoffs, known follow-ups. -->
