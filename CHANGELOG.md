# Changelog

All notable changes to Nyx Agent are documented here.

## 0.1.0 - Initial crates.io release

- Ships the `nyx-agent` CLI and loopback daemon.
- Runs local project scans through the external `nyx` static scanner.
- Stores runs, candidates, verification attempts, vulnerabilities, traces, and
  triage state in the local product store.
- Serves the embedded dashboard from the released binary.
- Includes the prebuilt frontend assets in the crates.io package so
  `cargo install nyx-agent` does not require Node or pnpm.
- Publishes internal implementation crates with versioned dependencies only to
  support installation of the binary crate. Those crates are not stable public
  APIs.
