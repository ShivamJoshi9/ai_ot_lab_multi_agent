from dataclasses import dataclass
from typing import Literal
 
Decision = Literal["ALLOW", "REVIEW", "BLOCK"]
 
ALLOWED_ACTIONS = {
    "search_advisory", "analyze_assets", "calculate_risk", "generate_report",
}
REVIEW_ACTIONS = {"propose_followup"}
BLOCKED_ACTIONS = {"isolate_server", "delete_logs", "modify_firewall"}
 
@dataclass(frozen=True)
class GuardrailResult:
    action: str
    decision: Decision
    reason: str
 
def check_action(action: str) -> GuardrailResult:
    if action in BLOCKED_ACTIONS:
        return GuardrailResult(action, "BLOCK", "Infrastructure modification is prohibited.")
    if action in REVIEW_ACTIONS:
        return GuardrailResult(action, "REVIEW", "Human approval is required.")
    if action in ALLOWED_ACTIONS:
        return GuardrailResult(action, "ALLOW", "Approved read-only or local training action.")
    return GuardrailResult(action, "BLOCK", "Unknown action. Default-deny policy applied.")
 
if __name__ == "__main__":
    print("\nADANI AGENT GUARDRAIL TEST")
    print("-" * 65)
    for action in ["search_advisory", "analyze_assets", "propose_followup", "isolate_server", "delete_logs", "modify_firewall", "unknown_tool"]:
        result = check_action(action)
        print(f"{result.action:22} {result.decision:7} {result.reason}")
