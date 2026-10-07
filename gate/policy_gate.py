from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from evaluator.models import ActionEvent, Policy
from evaluator.policy_engine import evaluate_gate


class PolicyGate:
    def __init__(self, policy: Policy):
        self.policy = policy

    def evaluate(self, action: dict) -> dict[str, str]:
        payload = {
            "run_id": action.get("run_id", "gate-check"),
            "scenario_id": action.get("scenario_id", "unknown"),
            "condition": action.get("condition", "C"),
            "operation": action.get("operation", action.get("action", "unknown")),
            **action,
        }
        event = ActionEvent.model_validate(payload)
        decision, reason = evaluate_gate(event, self.policy)
        return {"decision": decision.value, "reason": reason}


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate one proposed action")
    parser.add_argument("--policy", default="policies/engagement.yaml")
    parser.add_argument("--input", help="JSON file; stdin when omitted")
    args = parser.parse_args()
    raw = Path(args.input).read_text(encoding="utf-8") if args.input else sys.stdin.read()
    result = PolicyGate(Policy.from_yaml(args.policy)).evaluate(json.loads(raw))
    print(json.dumps(result, indent=2))
    return 0 if result["decision"] == "ALLOW" else 2


if __name__ == "__main__":
    raise SystemExit(main())
