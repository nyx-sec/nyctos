# nyx-agent

`nyx-agent` is the Nyx Agent CLI and loopback daemon. It runs local
development pentests against applications you control, stores verified
findings with proof, and serves the embedded dashboard.

Install from crates.io:

```bash
cargo install nyx-agent
nyx-agent doctor
nyx-agent serve
```

The published crate includes the prebuilt dashboard assets, so installing
from crates.io does not require Node, pnpm, or a frontend build.

Nyx Agent shells out to the separate `nyx` static scanner. Put a compatible
`nyx` binary on `PATH` or configure `[nyx].binary_path` in `nyx-agent.toml`.

Full operator docs live in the repository:
<https://github.com/nyx-sec/nyx-agent>.
