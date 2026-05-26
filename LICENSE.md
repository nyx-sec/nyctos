# Nyx Agent License

SPDX-License-Identifier: AGPL-3.0-or-later

Nyx Agent (the `nyx-agent` daemon, the web UI, and every accompanying file in this
repository unless otherwise noted) is open source software licensed under the
GNU Affero General Public License version 3 or, at your option, any later
version published by the Free Software Foundation.

You may use, study, copy, modify, and redistribute Nyx Agent under the AGPL terms.
If you modify Nyx Agent and run it as a network service, the AGPL requires you to
offer the corresponding source code for that modified version to users who
interact with it over a network.

The full AGPLv3 text is published by the Free Software Foundation:

<https://www.gnu.org/licenses/agpl-3.0.html>

## Commercial Licensing

Commercial licenses are available for organizations that want proprietary
embedding, private redistribution, hosted resale, custom support terms,
warranty terms, or other obligations outside the AGPL.

Contact <licensing@nyx.dev> with:

- Company name and legal entity
- Intended use: internal scans, CI, hosted service, embedded redistribution, or
  another deployment shape
- Deployment scope: repos, developer seats, scans per month, and environments
- Support needs: onboarding, private checks, custom reporting, or compliance
  review

## Contributions

Contributions are accepted under the [Nyx Agent Contributor License
Agreement](CLA.md). The CLA lets the maintainer keep Nyx Agent available under the
AGPL while also offering commercial licenses for organizations that need them.

## AI Providers

Nyx Agent does not include, proxy, sublicense, or resell access to Claude, Codex,
OpenAI, Anthropic, or any other model provider. AI runtimes are optional
operator-configured connectors. Users are responsible for using their own API
keys, local endpoints, or installed CLIs in compliance with the relevant
provider terms.

## Third-Party Software

Nyx Agent is built on third-party open source libraries. Each library retains its
own license.

The upstream `nyx` scanner is a separate GPL-3.0-or-later project. Nyx Agent
invokes `nyx` as an external scanner process rather than vendoring or linking
it as a library.
