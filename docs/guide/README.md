---
layout: doc
title: "User Guide"
permalink: /guide/
---

# superred User Guide

superred is a framework for **red-teaming AI systems**: you point an automated
attacker (an *optimizer*) at an AI system (a *target*) and measure whether the
attacker can make the system do something it should not, under a precisely
defined level of access (a *security domain scope*).

This guide is for people who want to **use** the framework: wrap their own AI
system as a target, write an attacker, define what counts as a successful
attack, and run evaluations. It assumes you can read Python and have seen
`asyncio` before, but it assumes no prior knowledge of superred.

If you instead want the internal design rationale (concurrency model, thread
safety, why each interface looks the way it does), read the design docs under
[`../docs/`](/reference/). This guide and those docs describe the
same code from two angles: this one is "how do I build something", that one is
"how and why does it work".

## The mental model in one paragraph

A **Target** is the AI system under test. It exposes labelled **injection
points** (controllables) and **readable facts** (observables), each tagged with
a **security domain** (a trust boundary). A **Task** sets the target up and
later judges whether the attack worked. A **SecurityClaim** is a bundle of
tasks. An **Optimizer** is the attacker: it receives events as the target runs
and decides what to inject. The **Controller** wires these together and runs one
**threat model**: one security-domain scope, with one attacker-LLM budget,
against one claim.

## Contents

1. [Quick Start](/guide/quick-start.html) - install and run an evaluation end to end
2. [Core Concepts](/guide/core-concepts.html) - the components and the run loop
3. [Writing a Target](/guide/writing-a-target.html) - wrap your AI system
4. [Writing an Optimizer](/guide/writing-an-optimizer.html) - build an attacker
5. [Writing Tasks and Security Claims](/guide/writing-tasks.html) - define what to test
6. [Running Evaluations](/guide/running-evaluations.html) - the Controller, results, persistence
7. [Security Domains](/guide/security-domains.html) - model real trust boundaries and scope what the attacker sees
8. [Advanced Patterns](/guide/advanced-patterns.html) - multi-turn, parallelism, packaging, sweeps

## How the pieces are packaged

The framework itself is the `superred` package. Everything you plug into it
(targets, optimizers, security claims) lives in **separate, independently
installable packages** in the `superred-modules/` repository, and the scripts
that wire specific combinations together live in `superred-experiments/`. You
will usually `pip install -e` the framework plus whichever modules you need,
then write a short experiment script. The [Quick Start](/guide/quick-start.html) shows
the smallest version of this.
