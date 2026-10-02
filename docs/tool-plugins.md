# Adding a new tool to Adi

1. Define an intent-based capability or reuse a common one.
2. Create `skills/NAME/tool.yaml`: name, binary, capabilities, risk, version_args, scope requirements, output format, bounded timeout/priority and normalized entities.
3. Write Skill V2: purpose, when to use/avoid, inputs, target types, risk/scope, important options, interpretation, false positives, common errors, rate/lockout limits, safe validation, related providers, fallback, versions and common outputs.
4. Write `adapter.py` with `build_argv(target, parameters, binary)`. Validate values; expose fixed typed operations. Never accept extra argv, shell strings, arbitrary modules or planner-supplied credentials.
5. Write `parser.py` with deterministic `parse` and preferably `parse_result` returning ParsedToolResult. Parsers produce common Observation types. Legacy list parsers remain compatible.
6. Add sanitized fixtures and meaningful malformed/partial/version/fallback tests. Classify risk and prove policy blocks before running a real local smoke test.
7. Review/install the skill in the built-in skills directory. No Orchestrator edit is needed.

Built-in contracts are checked for required files, capability declaration and recognized risk. `adi.tools.plugins.validate_plugin()` validates proposed local metadata/components without importing their Python modules, and returns LOCAL_DISCOVERED/untrusted metadata. The future locations `~/.adi/tools` and `.adi/tools` are not auto-loaded. Downloaded plugin code is never automatically executed.

TEMPORARY_INFERRED metadata is created only by the configured-name local help discovery helper. It cannot be installed as a reviewed provider merely by changing a YAML trust label. All target-facing execution requires an explicitly reviewed plugin installation. The metadata-validation API is preparation for future user plugin management, not a general plugin execution service.

Version arguments must be a reviewed, safe local probe. Unknown version keeps an installed executable available. Metadata/documentation and parser code changes require review even when the binary is unchanged.
