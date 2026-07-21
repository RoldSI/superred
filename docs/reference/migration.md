---
layout: doc
title: "Migration"
permalink: /reference/migration
---

# Migration

How to move your code across breaking releases. Each version below has its
own page with the specific changes and before/after migration steps.

For the authoritative, per-version record of everything that changed
(features, fixes, and breaking changes), see the [GitHub releases](https://github.com/RoldSI/superred/releases).

- [v0.3.0](/reference/migration/v0.3.0/): Live progress reporting, and a resumable results tree persisted by default.
- [v0.2.0](/reference/migration/v0.2.0/): The Controller becomes one threat model (`target_factory`, a single `scope` and `llm_config`), the attacker budget moves to `task_cost_cap_usd`, read-only scope arrives, plus several API renames.
