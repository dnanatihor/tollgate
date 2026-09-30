# Cursor prompts — Tollgate

Generated from SPEC.md by the portfolio bootstrap. Re-run the bootstrap after editing SPEC.md to refresh this file.

How to use: open this repository on its own in Cursor. For each phase, start a new chat in Agent mode, paste the **Build** prompt, and let it finish. Then paste the **Review** prompt. When every acceptance criterion is met, run the **Commit** command.

## Phase 0 — Scaffold, catalogs, and configuration

**Build**

```
Read SPEC.md. Implement Phase 0 from §16 only. Satisfy every acceptance criterion for Phase 0, write tests first where the spec gives expected outputs, and do not start later phases. If a phase starts with a spike, do the spike first and record it as an ADR. If anything is ambiguous, list the ambiguity and stop.
```

**Review**

```
Review the Phase 0 implementation against SPEC.md. For each acceptance criterion in §16, state whether it is met and which test proves it. List every divergence from the spec. Do not fix anything yet.
```

**Commit**

```
git add -A && git commit -m "feat(phase-0): scaffold, catalogs, and configuration"
```

## Phase 1 — Local diff pipeline and context

**Build**

```
Read SPEC.md. Implement Phase 1 from §16 only. Satisfy every acceptance criterion for Phase 1, write tests first where the spec gives expected outputs, and do not start later phases. If a phase starts with a spike, do the spike first and record it as an ADR. If anything is ambiguous, list the ambiguity and stop.
```

**Review**

```
Review the Phase 1 implementation against SPEC.md. For each acceptance criterion in §16, state whether it is met and which test proves it. List every divergence from the spec. Do not fix anything yet.
```

**Commit**

```
git add -A && git commit -m "feat(phase-1): local diff pipeline and context"
```

## Phase 2 — LLM layer, lenses, verification

**Build**

```
Read SPEC.md. Implement Phase 2 from §16 only. Satisfy every acceptance criterion for Phase 2, write tests first where the spec gives expected outputs, and do not start later phases. If a phase starts with a spike, do the spike first and record it as an ADR. If anything is ambiguous, list the ambiguity and stop.
```

**Review**

```
Review the Phase 2 implementation against SPEC.md. For each acceptance criterion in §16, state whether it is met and which test proves it. List every divergence from the spec. Do not fix anything yet.
```

**Commit**

```
git add -A && git commit -m "feat(phase-2): llm layer, lenses, verification"
```

## Phase 3 — Analyzers and deterministic architecture checks

**Build**

```
Read SPEC.md. Implement Phase 3 from §16 only. Satisfy every acceptance criterion for Phase 3, write tests first where the spec gives expected outputs, and do not start later phases. If a phase starts with a spike, do the spike first and record it as an ADR. If anything is ambiguous, list the ambiguity and stop.
```

**Review**

```
Review the Phase 3 implementation against SPEC.md. For each acceptance criterion in §16, state whether it is met and which test proves it. List every divergence from the spec. Do not fix anything yet.
```

**Commit**

```
git add -A && git commit -m "feat(phase-3): analyzers and deterministic architecture checks"
```

## Phase 4 — GitHub

**Build**

```
Read SPEC.md. Implement Phase 4 from §16 only. Satisfy every acceptance criterion for Phase 4, write tests first where the spec gives expected outputs, and do not start later phases. If a phase starts with a spike, do the spike first and record it as an ADR. If anything is ambiguous, list the ambiguity and stop.
```

**Review**

```
Review the Phase 4 implementation against SPEC.md. For each acceptance criterion in §16, state whether it is met and which test proves it. List every divergence from the spec. Do not fix anything yet.
```

**Commit**

```
git add -A && git commit -m "feat(phase-4): github"
```

## Phase 5 — Bitbucket Cloud

**Build**

```
Read SPEC.md. Implement Phase 5 from §16 only. Satisfy every acceptance criterion for Phase 5, write tests first where the spec gives expected outputs, and do not start later phases. If a phase starts with a spike, do the spike first and record it as an ADR. If anything is ambiguous, list the ambiguity and stop.
```

**Review**

```
Review the Phase 5 implementation against SPEC.md. For each acceptance criterion in §16, state whether it is met and which test proves it. List every divergence from the spec. Do not fix anything yet.
```

**Commit**

```
git add -A && git commit -m "feat(phase-5): bitbucket cloud"
```

## Phase 6 — Bitbucket Data Center

**Build**

```
Read SPEC.md. Implement Phase 6 from §16 only. Satisfy every acceptance criterion for Phase 6, write tests first where the spec gives expected outputs, and do not start later phases. If a phase starts with a spike, do the spike first and record it as an ADR. If anything is ambiguous, list the ambiguity and stop.
```

**Review**

```
Review the Phase 6 implementation against SPEC.md. For each acceptance criterion in §16, state whether it is met and which test proves it. List every divergence from the spec. Do not fix anything yet.
```

**Commit**

```
git add -A && git commit -m "feat(phase-6): bitbucket data center"
```

## Phase 7 — Evaluation, critic, and README

**Build**

```
Read SPEC.md. Implement Phase 7 from §16 only. Satisfy every acceptance criterion for Phase 7, write tests first where the spec gives expected outputs, and do not start later phases. If a phase starts with a spike, do the spike first and record it as an ADR. If anything is ambiguous, list the ambiguity and stop.
```

**README** (after the build prompt, in the same chat)

```
Read SPEC.md, including Appendix B. Write README.md following Appendix B.2 exactly, with the demo and results content from B.3. Take the Quickstart commands from what actually works in this repository, and add a CI job that runs them on a fresh checkout. For "Results / example output", run the tool on the included fixtures and paste the real output; do not invent any output. Leave docs/demo.gif as a placeholder with a TODO. Keep it under 150 lines and move anything longer into docs/.
```

**Review**

```
Review the Phase 7 implementation against SPEC.md. For each acceptance criterion in §16, state whether it is met and which test proves it. List every divergence from the spec. Do not fix anything yet.
```

**Commit**

```
git add -A && git commit -m "feat(phase-7): evaluation, critic, and readme"
```

## Phase 8 — Webhook service (optional)

**Build**

```
Read SPEC.md. Implement Phase 8 from §16 only. Satisfy every acceptance criterion for Phase 8, write tests first where the spec gives expected outputs, and do not start later phases. If a phase starts with a spike, do the spike first and record it as an ADR. If anything is ambiguous, list the ambiguity and stop.
```

**Review**

```
Review the Phase 8 implementation against SPEC.md. For each acceptance criterion in §16, state whether it is met and which test proves it. List every divergence from the spec. Do not fix anything yet.
```

**Commit**

```
git add -A && git commit -m "feat(phase-8): webhook service"
```
