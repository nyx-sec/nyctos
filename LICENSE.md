# Nyx Pro License

Nyx Pro (the `nyx-agent` daemon, the web UI, and every accompanying file in
this repository) is **source-available** software, not "open source".  The OSI
term *open source* refers exclusively to software distributed under an
OSI-approved license; Nyx Pro is not.  Approved phrasing for this software is
**source-available**, **fair-source**, or **public-source**.

Nyx Pro is governed by **PolyForm Small Business License 1.0.0** (reproduced
verbatim below).  In short:

- **Free** for personal use, research, hobby projects, OSS contribution, and
  any **small business** as defined by the license (organisation with fewer
  than 100 staff and less than $1,000,000 USD total revenue).
- **Commercial license required** for organisations above the small-business
  threshold and for any use the PolyForm Small Business terms do not cover.
  Contact <licensing@nyx.dev> (or the address in `CONTACT.md`) to negotiate
  commercial terms.
- **Source available** for everyone. Anyone may read, audit, and propose
  contributions. Forks and redistribution are permitted under the PolyForm
  terms.

The Nyx Pro daemon links to and orchestrates the separate `nyx` core scanner,
which is published under GPL-3.0-or-later.  The copyright holder of `nyx`
(Eli Peter, sole author) has executed an internal, project-to-project
dual-license grant authorising the Nyx Pro project to consume `nyx` under
non-GPL terms; that grant is recorded in `LICENSE-GRANTS.md` in the `nyx`
repository.  The grant is **not transferable**. Third-party forks of Nyx
Pro must comply with the public GPL-3.0-or-later terms of `nyx` (which are
viral copyleft on redistribution).

---

Copyright © 2026 Eli Peter.  All rights reserved.

---

## PolyForm Small Business License 1.0.0

<https://polyformproject.org/licenses/small-business/1.0.0>

### Acceptance

In order to get any license under these terms, you must agree to them as both
strict obligations and conditions to all your licenses.

### Copyright License

The licensor grants you a copyright license for the software to do everything
you might do with the software that would otherwise infringe the licensor's
copyright in it for any permitted purpose.  However, you may only distribute
the software according to *Distribution License* and make changes or new
works based on the software according to *Changes and New Works License*.

### Distribution License

The licensor grants you an additional copyright license to distribute copies
of the software.  Your license to distribute covers distributing the software
with changes and new works permitted by *Changes and New Works License*.

### Changes and New Works License

The licensor grants you the copyright licenses to:

1. Change the software; and
2. Make new works based on the software.

### Patent License

The licensor grants you a patent license for the software that covers patent
claims you might otherwise infringe by using the software for any permitted
purpose, in patents that the licensor can license, or becomes able to
license.

### Noncommercial Purposes

Any noncommercial purpose is a permitted purpose.

### Small Business

Use by any small business or for any small-business purpose is a permitted
purpose.

### Personal Uses

Personal use for research, experiment, and testing for the benefit of public
knowledge, personal study, private entertainment, hobby projects, amateur
pursuits, or religious observance, without any anticipated commercial
application, is use for a permitted purpose.

### Small Business definition

"Small business" means an organisation, including its affiliates, that has:

1. Fewer than 100 full-time-equivalent employees; and
2. Less than $1,000,000 USD (one million United States dollars) in total
   revenue (or local-currency equivalent) for the most recently completed
   annual reporting period.

### Notices

You must ensure that anyone who gets a copy of any part of the software from
you also gets a copy of these terms.

If you modify the software, you must include in any modified copies of the
software a prominent notice stating that you have modified the software.

### No Other Rights

These terms do not allow you to sublicense or transfer any of your licenses
to anyone else, or prevent the licensor from granting licenses to anyone
else.  These terms do not imply any other licenses.

### Patent Defense

If you make any written claim that the software infringes or contributes to
infringement of any patent, your patent license for the software granted
under these terms ends immediately.  If your company makes such a claim,
your patent license ends immediately for work on behalf of your company.

### Violations

The first time you are notified in writing that you have violated any of
these terms, or done anything with the software not covered by your
licenses, your licenses can nonetheless continue if you come into full
compliance with these terms, and take practical steps to correct past
violations, within 32 days of receiving notice.  Otherwise, all your
licenses end immediately.

### No Liability

***As far as the law allows, the software comes as is, without any warranty
or condition, and the licensor will not be liable to you for any damages
arising out of these terms or the use or nature of the software, under any
kind of legal claim.***

### Definitions

The **licensor** is the individual or entity offering these terms, and the
**software** is the software the licensor makes available under these terms.

**You** refers to the individual or entity agreeing to these terms.

**Your company** is any legal entity, sole proprietorship, or other kind of
organisation that you work for, plus all organisations that have control
over, are under the control of, or are under common control with that
organisation.  **Control** means ownership of substantially all the assets
of an entity, or the power to direct its management and policies by vote,
contract, or otherwise.  Control can be direct or indirect.

**Your licenses** are all the licenses granted to you for the software under
these terms.

**Use** means anything you do with the software requiring one of your
licenses.

---

## Commercial license

For organisations that do not qualify as a Small Business under PolyForm
Small Business 1.0.0, or for any use beyond what PolyForm permits (including
but not limited to: redistribution as part of a commercial offering,
hosted/managed service, OEM bundling, or removal of the source-available
restriction), a separate commercial license is available.

Contact the licensor at <licensing@nyx.dev> with:

- Company name + legal entity
- Approximate headcount + most recent annual revenue
- Intended use (internal SAST, CI, hosted service, embedded redistribution, etc.)
- Deployment scope (number of repos, developer seats, scans per month)

A commercial-license SKU is the only path that supersedes the PolyForm terms.

---

## Third-party software

Nyx Pro is built on a collection of third-party open-source libraries.  Each
library retains its original license; the full inventory is published in
`THIRD-PARTY-LICENSES.md` (generated at build time from `Cargo.lock`).  The
GPL-3.0-or-later `nyx` core scanner is consumed under an internal grant from
the copyright holder (see preamble above and `LICENSE-GRANTS.md` in the
`nyx` repository).
