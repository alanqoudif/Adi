"""Product layer: sits above the existing Adi Core (scope, orchestrator,
tools, evidence, findings, source intelligence) and exposes it as a
cohesive terminal product — events, the AI provider gateway, sessions,
the plain interactive shell, and (progressively) the Textual TUI.

Core must never import from `adi.product`. This package only consumes
Core's public surface (`adi.assessment.Assessment`, `adi.agent.*`,
`adi.llm.base.LLMProvider`, ...).
"""
