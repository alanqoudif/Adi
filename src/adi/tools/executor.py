"""Scope-authorized typed execution, sanitized evidence and bounded provider recovery."""
from __future__ import annotations

import asyncio
import hashlib
import json
import os

from adi.actions import ActionType, PlannedAction, RiskLevel
from adi.evidence.redaction import redact_secrets
from adi.knowledge.observations import Observation, ObservationType
from adi.reporting.redaction import known_secrets, redact_structure, redact_text
from adi.runtime.process import ExecutionResult
from adi.tools.intelligence import (
    PerformanceMemory,
    ToolEvidence,
    ToolFailure,
    TrustLevel,
    classify_failure,
    safe_target,
    sanitize_target,
)
from adi.tools.loader import load_adapter, load_parser


class ToolExecutionError(RuntimeError):
    pass


class ScopeViolationError(ToolExecutionError):
    def __init__(self, reason: str):
        super().__init__(f'blocked by scope engine: {reason}')
        self.reason = reason


class ToolExecutor:
    def __init__(self, registry, runtime, scope_engine, workspace, raw_output_dir,
                 rate_limiter=None):
        self.registry, self.runtime = registry, runtime
        self.scope_engine, self.workspace = scope_engine, workspace
        self.raw_output_dir = raw_output_dir
        raw_output_dir.mkdir(parents=True, exist_ok=True)
        self.rate_limiter = rate_limiter
        self.memory = PerformanceMemory(raw_output_dir.parent / 'tool-performance.json')
        registry.memory = self.memory
        self._runtime_detected = False
        self._execution_guard = asyncio.Lock()

    async def run_capability(self, capability, target, parameters=None, reason_summary=''):
        await self._detect()
        candidates = self.registry.ranked(capability)
        if capability == 'audit_credentials' and (parameters or {}).get('service') == 'http-get':
            candidates = [t for t in candidates if t.metadata.name != 'medusa']
        if not candidates:
            # Still record the policy decision even if providers are absent.
            decision = self.scope_engine.authorize(PlannedAction(
                action_type=ActionType.RUN_TOOL, capability=capability, target=target,
                parameters=parameters or {}))
            if not decision.allowed:
                self.workspace.record_action(action_type='run_tool', capability=capability,
                    tool='', target=sanitize_target(target), parameters_json='{}', reason_summary=reason_summary,
                    scope_allowed=False, scope_reason=decision.reason, status='blocked')
                raise ScopeViolationError(decision.reason)
            raise ToolExecutionError(f'no safe available provider for {capability}')
        for index, tool in enumerate(candidates[:3]):
            unavailable = [t.metadata.name for t in self.registry.by_capability(capability) if not t.available]
            incompatible = [t.metadata.name for t in self.registry.by_capability(capability)
                            if self.memory.get(t).disabled]
            why = (f'{reason_summary}; capability {capability}; reviewed provider {tool.metadata.name}; '
                   f'preferred output {tool.metadata.output.preferred_format}; risk {tool.metadata.risk_level}; '
                   f'runtime {tool.runtime}; unavailable providers: {", ".join(unavailable) or "none"}; '
                   f'incompatible providers: {", ".join(incompatible) or "none"}')
            if index:
                why += '; fallback after unavailable/incompatible provider'
            observations = await self.run(tool.metadata.name, target, parameters,
                                          capability=capability, reason_summary=why)
            errors = [o.value.get('failure') for o in observations if o.type == ObservationType.TOOL_ERROR]
            if not errors or any(e not in {ToolFailure.UNSUPPORTED_VERSION.value,
                                          ToolFailure.NOT_INSTALLED.value,
                                          ToolFailure.PARSER_FAILURE.value} for e in errors):
                return observations
        return observations

    async def _detect(self):
        if not self._runtime_detected:
            await self.registry.detect_runtime(self.runtime)
            self._runtime_detected = True

    async def run(self, tool_name, target, parameters=None, capability='', reason_summary=''):
        async with self._execution_guard:
            previous = len(self.workspace.list_actions())
            try:
                return await self._run(tool_name, target, parameters, capability, reason_summary)
            except ScopeViolationError:
                raise
            except (ToolExecutionError, ValueError, OSError) as exc:
                actions = self.workspace.list_actions()
                if len(actions) == previous:
                    action = PlannedAction(action_type=ActionType.RUN_TOOL,
                                           capability=capability, target=target, tool=tool_name)
                    decision = self.scope_engine.authorize(action)
                    self.workspace.record_action(action_type='run_tool', capability=capability,
                        tool=tool_name, target=sanitize_target(target), parameters_json='{}',
                        reason_summary='typed tool request rejected before execution',
                        scope_allowed=decision.allowed, scope_reason=decision.reason,
                        status='failed' if decision.allowed else 'blocked')
                elif actions[-1].status == 'running':
                    self.workspace.update_action_result(actions[-1].id, exit_code=-1,
                        timed_out=False, stdout_path=None, stderr_path=None, status='failed')
                if isinstance(exc, ToolExecutionError):
                    raise
                raise ToolExecutionError('typed tool request or runtime failure') from exc

    async def _run(self, tool_name, target, parameters=None, capability='', reason_summary=''):
        await self._detect()
        parameters = parameters or {}
        tool = self.registry.get(tool_name)
        if tool is None:
            raise ToolExecutionError(f"unknown tool '{tool_name}' — is its skill registered?")
        if 'source' in tool.metadata.category:
            raise ToolExecutionError('source tools require SourceScanner; raw runtime output is forbidden')
        if tool.metadata.trust_level != TrustLevel.BUILT_IN_REVIEWED:
            raise ToolExecutionError('temporary tools require reviewed execution support')
        actual_capability = capability or tool.metadata.capabilities[0]
        if actual_capability not in tool.metadata.capabilities:
            raise ToolExecutionError('tool does not provide requested capability')
        # Elevated adapters cannot disguise their capability in planner parameters.
        if tool.metadata.scope_requirements.explicit_auth_testing_permission:
            actual_capability = 'audit_credentials'
        decision = self.scope_engine.authorize(PlannedAction(
            action_type=ActionType.RUN_TOOL, capability=actual_capability, target=target,
            tool=tool_name, parameters=parameters, risk=RiskLevel(tool.metadata.risk_level)))
        if not decision.allowed:
            self.workspace.record_action(action_type='run_tool', capability=actual_capability,
                tool=tool_name, target=sanitize_target(target), parameters_json='{}', reason_summary=reason_summary,
                scope_allowed=False, scope_reason=decision.reason, status='blocked')
            raise ScopeViolationError(decision.reason)
        try:
            safe_target(target)
        except ValueError as exc:
            raise ToolExecutionError('invalid target: one explicit host required') from exc
        actions = [a for a in self.workspace.list_actions() if a.action_type == 'run_tool']
        scope = self.scope_engine.scope
        if len(actions) >= scope.max_tool_runs or len(self.workspace.list_actions()) >= scope.max_actions:
            raise ToolExecutionError('assessment tool budget exhausted')
        if tool.metadata.requires_network and len(actions) >= scope.max_network_tool_runs:
            raise ToolExecutionError('network tool budget exhausted')
        if (actual_capability == 'audit_credentials'
                and sum(a.capability == actual_capability for a in actions) >= scope.max_elevated_actions):
            raise ToolExecutionError('elevated action budget exhausted')
        if not tool.available:
            raise ToolExecutionError(f"tool '{tool_name}' is not installed/available on this runtime")
        if (tool.metadata.requires_root and actual_capability != 'inspect_pcap'
                and (tool.runtime != 'local' or os.geteuid() != 0)):
            raise ToolExecutionError('tool requires local privileges; no automatic sudo')
        if self.memory.get(tool).disabled:
            raise ToolExecutionError('provider incompatible in this assessment; select fallback')
        if actual_capability == 'audit_credentials':
            from adi.tools.authentication import execute_audit
            try:
                return await execute_audit(self, tool, target, parameters, actual_capability, reason_summary)
            except ValueError as exc:
                raise ToolExecutionError('invalid or stopped credential audit request') from exc
        parameters = dict(parameters)
        if tool_name in {'ffuf', 'feroxbuster'}:
            parameters['threads'] = min(int(parameters.get('threads', 1)), scope.rate_limits.concurrent_tools)
            parameters['rate'] = int(scope.rate_limits.requests_per_second)
            if parameters['rate'] < 1:
                raise ToolExecutionError('tool cannot honor a sub-one-request/second scope rate')
        if tool_name == 'nmap':
            parameters['max_rate'] = scope.rate_limits.requests_per_second
        if tool_name == 'nuclei':
            parameters['rate_limit'] = max(1, int(scope.rate_limits.requests_per_second))
        try:
            argv = self._build_argv(tool, target, parameters)
        except Exception as exc:
            raise ToolExecutionError(f"invalid typed request for {tool_name}") from exc
        timeout = min(tool.metadata.execution.timeout_seconds,
                      scope.rate_limits.max_tool_runtime_seconds)
        if actual_capability == 'capture_network_metadata':
            timeout = min(timeout, int(parameters['duration']))
        action_id = self._begin_action(tool, target, parameters, actual_capability, reason_summary)
        result = await self._execute(argv, timeout)
        parsed = self._parse(tool, result, target)
        failure = classify_failure(result.stderr, result.exit_code, result.timed_out)
        if any(o.type == ObservationType.TOOL_ERROR for o in parsed):
            failure = failure or ToolFailure.PARSER_FAILURE
        return self._record_execution(tool, target, parameters, actual_capability, reason_summary,
                                      result, parsed, failure, action_id=action_id)

    async def _execute(self, argv, timeout, cwd=None):
        if self.rate_limiter:
            async with self.rate_limiter.concurrency_guard():
                await self.rate_limiter.acquire()
                return await self.runtime.execute(argv, timeout=timeout, cwd=cwd)
        return await self.runtime.execute(argv, timeout=timeout, cwd=cwd)

    def _build_argv(self, tool, target, parameters):
        adapter = load_adapter(tool.metadata.skill_dir)
        return adapter.build_argv(target=target, parameters=parameters,
                                  binary=tool.binary_path or tool.metadata.name)

    def _parse(self, tool, result, target):
        try:
            parser = load_parser(tool.metadata.skill_dir)
            parse_fn = getattr(parser, "parse_result", parser.parse)
            parsed = parse_fn(stdout=result.stdout, stderr=result.stderr,
                                  context={'target': target, 'exit_code': result.exit_code})
            return parsed.observations if hasattr(parsed, 'observations') else parsed
        except Exception:  # noqa: BLE001 - deterministic parser boundary
            return [Observation(type=ObservationType.TOOL_ERROR, subject=target,
                value={'tool': tool.metadata.name, 'failure': 'PARSER_FAILURE'},
                source=tool.metadata.name)]

    def _begin_action(self, tool, target, parameters, capability, reason):
        scope = self.scope_engine.scope
        all_actions = self.workspace.list_actions()
        tool_actions = [a for a in all_actions if a.action_type == 'run_tool']
        if len(all_actions) >= scope.max_actions or len(tool_actions) >= scope.max_tool_runs:
            raise ToolExecutionError('assessment action budget exhausted')
        if (capability == 'audit_credentials' and
                sum(a.capability == capability for a in tool_actions) >= scope.max_elevated_actions):
            raise ToolExecutionError('elevated action budget exhausted')
        parameters = json.loads(redact_secrets(json.dumps(parameters)))
        return self.workspace.record_action(action_type='run_tool', capability=capability,
            tool=tool.metadata.name, target=target, parameters_json=json.dumps(parameters),
            reason_summary=redact_secrets(reason), scope_allowed=True, scope_reason='within scope',
            status='running')

    def _record_execution(self, tool, target, parameters, capability, reason, result, observations,
                          failure, action_id=None):
        action_id = action_id or self._begin_action(tool, target, parameters, capability, reason)
        # Universal redaction happens before disk AND before normalized workspace storage.
        secrets = known_secrets(self.scope_engine.scope)
        result.stdout, result.stderr = redact_text(result.stdout, secrets), redact_text(result.stderr, secrets)
        for obs in observations:
            obs.value = redact_structure(obs.value, secrets)
        if failure and not any(o.type == ObservationType.TOOL_ERROR for o in observations):
            observations.append(Observation(type=ObservationType.TOOL_ERROR, subject=target,
                value={'tool': tool.metadata.name, 'failure': failure.value}, source=tool.metadata.name))
        for obs in observations:
            if obs.type == ObservationType.TOOL_ERROR and failure:
                obs.value['failure'] = failure.value
        self._persist_raw(action_id, result)
        self.workspace.update_action_result(action_id, exit_code=result.exit_code,
            timed_out=result.timed_out, stdout_path=result.stdout_path, stderr_path=result.stderr_path,
            status='completed' if failure is None else 'failed')
        ids = self.workspace.record_observations(observations)
        evidence = ToolEvidence(action_id=action_id, tool=tool.metadata.name, version=tool.version,
            runtime=tool.runtime, capability=capability, target=target, selection_reason=redact_text(reason, secrets),
            scope_decision='within scope', sanitized_argv=[redact_text(x, secrets) for x in result.argv],
            started_at=result.started_at.isoformat(), completed_at=result.completed_at.isoformat(),
            exit_code=result.exit_code,
            failure=ToolFailure.PARTIAL_SUCCESS if failure and any(o.type != ObservationType.TOOL_ERROR for o in observations)
                    and failure not in {ToolFailure.LOCKOUT_SIGNAL, ToolFailure.RATE_LIMITED} else failure,
            failure_cause=failure, partial=bool(failure and any(o.type != ObservationType.TOOL_ERROR for o in observations)),
            parsed_observation_ids=ids,
            raw_reference=result.stdout_path)
        self.workspace.record_evidence(type='tool_result', source=tool.metadata.name, subject=target,
            summary=f'{capability}: {len(ids)} observations', raw_reference=result.stdout_path,
            sanitized_preview=result.stdout[:1000],
            hash=hashlib.sha256(result.stdout.encode()).hexdigest(), metadata_json=evidence.model_dump_json())
        self.memory.record(tool, failure, result.duration_seconds)
        return observations

    def _persist_raw(self, action_id: str, result: ExecutionResult):
        for stream in ('stdout', 'stderr'):
            path = self.raw_output_dir / f'{action_id}.{stream}.txt'
            path.write_text(getattr(result, stream))
            setattr(result, stream + '_path', str(path))
