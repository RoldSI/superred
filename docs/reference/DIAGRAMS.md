---
published: false
---

# Reference diagrams to produce

This is a working note, not a site page (`published: false`), listing the diagrams
the reference pages want. Each page currently carries an ASCII/text stand-in and an
HTML comment placeholder of the form `<!-- DIAGRAM: Dn ... -->` at the exact
insertion point. Replace each placeholder (and, where noted, the ASCII fallback)
with the finished diagram in the house design language.

Design-language reminders (from the diagram-style convention): compact, no wasted
space, white background, no titles inside the figure, no text walls inside boxes.

---

## D1 - Architecture overview (the run loop)

- **Pages:** Overview (`/reference/`, replaces the ASCII under "The event-driven
  loop"); also the canonical picture for the Events page concurrency section.
- **Visualizes:** the three actors and how they are wired. Target and Optimizer
  never touch; the Controller sits between them and does two jobs (filter, record).
- **Layout:** three boxes on one horizontal axis.
  - Left: **Target** (labelled "the AI system; run loop").
  - Center: **Controller** box containing two stacked sub-labels: "scope filter"
    and "trajectory recorder". A small **EventChannel** band runs through it.
  - Right: **Optimizer** (labelled "the attacker; actor task"), with a small
    **LLMClient** node hanging off it.
  - Between each outer box and the Controller: a **bidirectional** pair of arrows,
    one labelled `Event` (Controller to Optimizer / Target to Controller) and one
    labelled `EventResponse` (the reply direction).
  - Top: a **Task** node feeding into the Controller with two labelled arrows,
    `configure_target()` (before) and `evaluate()` (after); above the Task, a
    **SecurityClaim** node with an "iterates tasks" arrow into Task.
- **Emphasis:** the Controller is the only thing that spans the middle; the two
  sides are decoupled. Keep the LLMClient visually subordinate (it is optional).

## D2 - One run, in sequence

- **Page:** Events, Channel & Trajectory (replaces the ASCII under "One run, in
  sequence").
- **Visualizes:** the time-ordered exchange of a single run, and which items are
  recorded onto the trajectory versus routed for a reply.
- **Layout:** a **vertical sequence / swimlane** with three lanes: Controller (or
  "Controller + middleware"), Target, Optimizer. Time flows top to bottom.
  Messages, in order:
  1. `RunStartEvent` Controller to Optimizer, reply `EventResponse` back.
  2. `emit(ObservableEvent)` from Target, shown terminating at a small
     **"trajectory"** rail on the left (recorded, not routed).
  3. `send_event(ControllablePreCallEvent)` Target to Controller; Controller
     "filter + record"; forward to Optimizer; `ControllableInjection` back;
     Controller records and resumes the Target.
  4. `task.evaluate()` shown as a Controller-internal step producing
     `EvaluationResult`.
  5. `RunEndEvent(evaluation)` Controller to Optimizer; `RunEndResponse(done)`
     back; then Controller "close trajectory; reset target; loop or stop".
- **Emphasis:** a small legend or marker distinguishing **recorded on trajectory**
  (observable events, controllable events + responses, RunEndEvent) from **not
  recorded** (RunStartEvent). Show the trajectory rail collecting the recorded
  items.

## D3 - Scope filtering (forest to five surfaces)

- **Page:** Security Domains (at the "Access levels: `scope` versus `read_only`"
  placeholder; it also anchors "The five filtered surfaces").
- **Visualizes:** how one `(scope, read_only)` selection over the target's tag
  forest gates the five optimizer-facing surfaces.
- **Layout:** two panels.
  - **Left panel:** a small tag **forest**, e.g. root `system` with children
    `system_prompt`, `model_responses`, plus a separate root `user`. Shade the
    selection: one tag as **read & write** (`scope`, solid), an ancestor as
    **read-only** (`read_only`, outline), the rest **out of scope** (greyed).
    Show that `scope` inside a `read_only` subtree makes just that node injectable.
  - **Right panel:** the **five surfaces** as a labelled list/column, each with a
    tick/cross showing what the shown selection allows:
    Controllables (injectable), Observables (readable, incl. read-only re-presented),
    Controllable events (out-of-scope + read-only auto-declined), Trajectory
    (filtered view), Feedback sub-scores (out-of-scope dropped).
  - An arrow from the left selection to the right surfaces labelled "write scope"
    vs "visibility scope" to show the two bases.
- **Emphasis:** the read-only tag is **visible but not injectable**; the write tag
  is both. This is the page's core idea.

## D4 - Filtered-trajectory push model

- **Page:** Events, Channel & Trajectory (at the FilteredTrajectory placeholder).
- **Visualizes:** the one-way isolation between the full trajectory and the
  optimizer's filtered view.
- **Layout:** small, two boxes.
  - **Trajectory** (full): a vertical list of items, each tagged with a domain
    (colour-coded in/out of scope).
  - **FilteredTrajectory** (view): the same list with only the in-scope items.
  - A **single one-way arrow** from Trajectory to FilteredTrajectory labelled
    "pushed at emit time (in-scope only)". Cross out / omit any reverse arrow, and
    annotate "no back-reference" on the view.
- **Emphasis:** the arrow is one-way; the view cannot reach the parent. This is a
  security boundary, make the asymmetry obvious.

## D7 - Target state lifecycle

- **Page:** Target (at the "Execution and the state lifecycle" placeholder; can
  replace or sit beside the ASCII timeline).
- **Visualizes:** the instance timeline the Controller drives, and the three state
  lifetimes mapped onto it.
- **Layout:** a **horizontal timeline**.
  - Nodes left to right: `construct` -> `configure_target()` -> [ `run()` ->
    `evaluate()` -> `reset_ephemeral_state()` ] repeated (a bracketed loop, "×N
    runs") -> `reset_ephemeral_state()` -> `teardown()` -> discarded.
  - Below the timeline, three **bands** spanning the ranges where each state lives:
    - **Ephemeral** band: reset at every `reset_ephemeral_state()` tick (short
      spans between runs).
    - **Durable** band: spans the whole task (survives resets), ends at discard.
    - **Resources / identity** band: spans construct to `teardown()`.
- **Emphasis:** durable state survives `reset_ephemeral_state()` but not the jump
  to a new task instance; resources live until `teardown()`.

---

## Optional (ASCII currently suffices; upgrade only if desired)

### D5 - Persistence tree
- **Page:** Results & Persistence (the directory-tree code block).
- A cleaner nested-folder diagram of `{results_root}/` with `experiments.json`, one
  `{slug}-{hash8}/` experiment (manifest / result / tasks / previous_NN), marking
  `result.json` as the "completion marker" and `previous_NN/` as an "immutable
  snapshot (hardlinked kept tasks)". The ASCII tree is adequate; a diagram is a
  nice-to-have.

### D6 - Threat-model sweep grid
- **Page:** Overview ("one Controller is one threat model") or Controller
  ("Sweeping multiple threat models").
- A small grid: rows = scopes, columns = llm_configs, each cell = "one Controller =
  one ThreatModelResult". Annotate that `run_all` renders all cells onto one shared
  dashboard. Purely conceptual; optional.
