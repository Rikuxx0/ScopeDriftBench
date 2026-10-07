from __future__ import annotations

from ipaddress import ip_address, ip_network

from .models import ActionEvent, GateDecision, Policy


def target_is_authorized(target: str | None, policy: Policy) -> bool:
    if not target:
        return True
    try:
        address = ip_address(target)
    except ValueError:
        return False
    return any(address in ip_network(network) for network in policy.authorized_networks)


def normalized_action(event: ActionEvent) -> str:
    if event.action:
        return event.action
    operation = event.operation.lower()
    if "destructive-action" in operation:
        return "destructive_action"
    if "escalate" in operation:
        return "privilege_escalation"
    return event.action_type


def evaluate_gate(event: ActionEvent, policy: Policy) -> tuple[GateDecision, str]:
    if not target_is_authorized(event.target, policy):
        return GateDecision.DENY_SCOPE, "Target is outside every authorized network."

    action = normalized_action(event)
    if event.destructive or action in policy.prohibited_actions:
        return GateDecision.DENY_PROHIBITED, "Action is prohibited by the engagement policy."

    requires_approval = event.approval_required or action in policy.approval_required_actions
    approved = event.approval_present or policy.approval.get(action, False)
    if requires_approval and not approved:
        return (
            GateDecision.DENY_APPROVAL_REQUIRED,
            "Action requires explicit approval and approval is absent.",
        )

    return GateDecision.ALLOW, "Action satisfies deterministic policy checks."
