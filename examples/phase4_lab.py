"""Local Phase 4 acceptance demo; deterministic planner fixture, real assessment stack.

Run: python examples/phase4_lab.py --output .adi/phase4-demo
No real LLM is claimed here. The fixture implements the provider protocol
only to select controlled actions; no finding/evidence rows are inserted.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "webapp"))
from app import DemoApp


def action(kind, reason, **extra):
    return {"action_type": kind, "reason_summary": reason,
            "expected_information_gain": reason, **extra}


def steps(base):
    result = [action("http_request", "Discover the local controlled order resources and declared ownership.",
                     target=base, parameters={"url": base + "/phase4"})]
    for user in ("user_a", "user_b"):
        result.append(action("http_request", f"Establish the authorized local {user} test identity.",
                             target=base, parameters={"url": base + "/api/login", "method": "POST",
                             "session_id": user, "body": f"username={user}"}))
    for mode in ("broken", "safe"):
        path = f"/api/orders-{mode}/1"
        result.append(action("http_request", "Observe the controlled owner's baseline resource.",
                             target=base, parameters={"url": base + path, "session_id": "user_a"}))
        title = "Possible object authorization failure on " + path
        result.append(action("investigate_hypothesis",
                             f"Discovery exposes {path}; the lab declares order 1 owned by user_a. Test whether user_b can read it.",
                             parameters={"title": title, "category": "broken_object_authorization",
                                         "confidence": 0.65, "validation_plan": [
                                             "Request controlled order 1 as owner user_a, then as user_b.",
                                             "Expect user_b to receive 401/403/404; stop after the comparison."]}))
        result.append(action("verify_finding", "Compare owner and non-owner sessions for one controlled object.",
                             hypothesis_title=title, parameters={"validation_action_type": "check_object_authorization",
                             "validation_parameters": {"url": base + path, "owner_session": "user_a", "other_session": "user_b"}}))
        result.append(action("verify_finding", "Apply the evidence verifier and required critic before deciding.",
                             hypothesis_title=title, parameters={"mode": "finalize", "affected_endpoints": [path]}))
    result += [action("generate_report", "Write confirmed, rejected and secure-control results from persistent state."),
               action("complete", "Both controlled authorization questions are resolved; stop testing.")]
    return result


class PlannerFixture:
    """A deterministic provider fixture, explicitly not a real model."""
    def __init__(self, base, prefix_actions=()):
        planned = iter([*prefix_actions, *steps(base)])

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_GET(self):
                body = json.dumps({"data": [{"id": "deterministic-phase4-fixture"},
                                              {"id": "fixture-alternate"}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_POST(self):
                request = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                messages = request["messages"]
                if messages == [{"role": "user", "content": "Reply OK"}]:
                    reply = "OK"
                elif '"title": "CriticReview"' in messages[-1]["content"]:
                    reply = {"decision": "accept", "concerns": [], "additional_validation_needed": []}
                else:
                    reply = next(planned)
                    title = reply.pop("hypothesis_title", None)
                    if title:
                        context = messages[1]["content"]
                        match = re.search(re.escape(title) + r"[^\n]*id=(hyp-[a-f0-9]+)", context)
                        if not match:
                            raise RuntimeError("Planner fixture could not resolve the persisted hypothesis")
                        reply["related_hypothesis_id"] = match.group(1)
                body = json.dumps({"choices": [{"message": {"content": json.dumps(reply)}}]}).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return f"http://127.0.0.1:{self.server.server_port}/v1"

    def __exit__(self, *args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


def run_demo(output: Path) -> dict:
    output = output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    (output / ".adi.yaml").write_text("runtime:\n  type: local\n  allow_local: true\n")
    demo = DemoApp().start()
    env = dict(os.environ)
    env.update(ADI_LLM_PROVIDER="openai-compatible", ADI_LLM_MODEL="deterministic-phase4-fixture", ADI_LLM_API_KEY="")
    env["PYTHONPATH"] = str(ROOT / "src")
    logs = []

    def cli(*args):
        proc = subprocess.run([sys.executable, "-m", "adi.cli", *args], cwd=output,
                              env=env, text=True, capture_output=True, timeout=90, check=True)
        logs.append("adi " + " ".join(args) + "\n" + proc.stdout)
        return proc.stdout

    try:
        with PlannerFixture(demo.base_url) as provider_url:
            env["ADI_LLM_BASE_URL"] = provider_url
            lab_output = cli("lab", demo.base_url, "--autonomous", "--name", "local-phase4-lab", "--max-actions", "20")
        assessment_id = re.search(r"Assessment created:\s*(assess-[a-f0-9]+)", lab_output).group(1)
        if "confirmed" not in lab_output or "rejected" not in lab_output:
            raise AssertionError("Autonomous path did not resolve both hypotheses")
        # These invocations are separate processes. No assessment object survives.
        cli("resume", assessment_id)
        cli("report", assessment_id)
        cli("findings", assessment_id)
        cli("finding", assessment_id, "ADI-F-001")
        cli("hypothesis", assessment_id, "ADI-H-002")
        cli("evidence", assessment_id, "EV-001")
        cli("teach", assessment_id, "ADI-H-002")
        directory = output / ".adi" / "assessments" / assessment_id
        report = json.loads((directory / "reports" / "report.json").read_text())
        assert len(report["findings"]) == 1
        assert len(report["rejected_hypotheses"]) == 1
        assert len(report["positive_security_observations"]) == 1
        assert report["activity_summary"]["validation_actions"] == 2
        assert report["activity_summary"]["critic_reviews"] == 1
        assert report["findings"][0]["critic_summary"] == "accept"
        assert report["findings"][0]["severity"] == "high"
        assert report["assessment"]["status"] == "completed"
        (output / "acceptance.log").write_text("\n".join(logs))
        result = {"assessment_id": assessment_id, "target": demo.base_url,
                  "planner": "deterministic localhost provider fixture (not a real model)",
                  "report_directory": str(directory / "reports"),
                  "findings": report["findings"], "rejected": report["rejected_hypotheses"],
                  "positive_controls": report["positive_security_observations"],
                  "evidence": report["evidence_index"]}
        (output / "acceptance.json").write_text(json.dumps(result, indent=2))
        return result
    finally:
        demo.stop()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(".adi/phase4-demo"))
    result = run_demo(parser.parse_args().output)
    print(json.dumps(result, indent=2))
