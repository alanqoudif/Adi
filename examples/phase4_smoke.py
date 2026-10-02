"""Check configured real planner against a safe, isolated local Phase 4 lab."""
from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

from adi.actions import ActionType
from adi.agent.planner import Planner
from adi.assessment import Assessment
from adi.config.settings import load_config
from adi.llm.base import LLMError, MalformedResponseError
from adi.llm.router import ProviderNotConfiguredError, build_provider
from adi.scope.models import Scope

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests" / "fixtures" / "webapp"))
from app import DemoApp


async def smoke():
    config = load_config()
    selected = config.models.planner or config.provider
    result = {"provider": os.getenv("ADI_LLM_PROVIDER", selected.type),
              "model": os.getenv("ADI_LLM_MODEL", selected.model), "valid_structured_action": None}
    output = Path(".adi/phase4-smoke.json")
    output.parent.mkdir(parents=True, exist_ok=True)
    try:
        llm = build_provider(config)
    except ProviderNotConfiguredError:
        result["status"] = "Real-model smoke test skipped: provider credentials unavailable."
    else:
        demo = DemoApp().start()
        try:
            assessment = Assessment.create(Scope(name="real-model-phase4-smoke", targets=[demo.base_url], max_actions=1), config)
            orchestrator = assessment.build_orchestrator(llm)
            h = orchestrator.hypothesis_engine.create(title="Possible missing authentication on controlled /api/private", category="missing_authentication")
            context = orchestrator.context_builder.build()
            context.goal = (f"Test only anonymous access to {demo.base_url}/api/private using verify_finding, "
                            f"hypothesis_id={h.id}, validation_action_type=check_auth_boundary, "
                            "validation_parameters containing that exact URL. This lab should return 401. No other action is authorized.")
            planned = await asyncio.wait_for(Planner(llm).plan(context), timeout=60)
            result["valid_structured_action"] = True
            result["action_type"] = planned.action_type.value
            p = planned.parameters
            if (planned.action_type == ActionType.VERIFY_FINDING
                    and (planned.related_hypothesis_id or p.get("hypothesis_id")) == h.id
                    and p.get("mode", "validate") == "validate"
                    and p.get("validation_action_type") == "check_auth_boundary"
                    and p.get("validation_parameters") == {"url": demo.base_url + "/api/private"}):
                outcome = await orchestrator._dispatch(planned)
                result["status"] = outcome.status
                result["validation_result"] = outcome.detail
            else:
                result["status"] = "valid structured action; outside smoke allow-list, not executed"
            result["assessment_id"] = assessment.id
        except (LLMError, MalformedResponseError, TimeoutError):
            result["valid_structured_action"] = False
            result["status"] = "failed: planner request failed or returned invalid structured action"
        finally:
            demo.stop()
    output.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    asyncio.run(smoke())
