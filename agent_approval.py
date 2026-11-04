import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from agent_guardrails import check_action
from agent_tools import execute_tool
 
BASE = Path(__file__).resolve().parent
AUDIT_DIR = BASE / "reports" / "agent_audit"
AUDIT_DIR.mkdir(parents=True, exist_ok=True)
 
def record_event(event):
    """Save one immutable-named training audit record."""
    event = dict(event)
    event["event_id"] = str(uuid.uuid4())
    event["timestamp_utc"] = datetime.now(timezone.utc).isoformat()
    path = AUDIT_DIR / f"{event['event_id']}.json"
    path.write_text(json.dumps(event, indent=2), encoding="utf-8")
    return event
 
def demonstrate_guardrail(action, argument):
    result = execute_tool(action, argument)
    event = record_event({"event_type": "GUARDRAIL_TEST", "action": action, "argument": argument, "decision": result["status"], "message": result["message"], "simulation": True})
    return result, event
 
def create_followup_proposal(cve, description):
    cve = cve.strip().upper()
    description = description.strip()
    if not cve or not description:
        raise ValueError("CVE and description are required.")
    policy = check_action("propose_followup")
    if policy.decision != "REVIEW":
        raise RuntimeError("Unexpected guardrail policy.")
    return record_event({"event_type": "FOLLOWUP_PROPOSAL", "cve": cve, "description": description, "action": "propose_followup", "status": "PENDING", "simulation": True})
 
def decide_proposal(proposal_id, decision):
    if decision not in {"APPROVE", "REJECT"}:
        raise ValueError("Decision must be APPROVE or REJECT.")
    try:
        uuid.UUID(proposal_id)
    except (ValueError, AttributeError):
        raise ValueError("Invalid proposal identifier.")
    proposal_file = AUDIT_DIR / f"{proposal_id}.json"
    if not proposal_file.exists():
        raise ValueError("Proposal not found.")
    proposal = json.loads(proposal_file.read_text(encoding="utf-8"))
    if proposal.get("event_type") != "FOLLOWUP_PROPOSAL":
        raise ValueError("This record is not a proposal.")
    for path in AUDIT_DIR.glob("*.json"):
        event = json.loads(path.read_text(encoding="utf-8"))
        if event.get("event_type") == "HUMAN_DECISION" and event.get("proposal_id") == proposal_id:
            raise ValueError("Proposal already reviewed.")
    return record_event({"event_type": "HUMAN_DECISION", "proposal_id": proposal_id, "decision": decision, "execution_status": "NOT_EXECUTED", "simulation": True})
 
if __name__ == "__main__":
    print("\nADANI AGENT GUARDRAIL DEMONSTRATION\n" + "=" * 55)
    for action, argument in [("search_advisory", "CVE-2021-44228"), ("propose_followup", "Review affected assets"), ("isolate_server", "AST-004"), ("modify_firewall", "allow-all"), ("unknown_action", "test")]:
        result, event = demonstrate_guardrail(action, argument)
        print(f"{action:22} -> {result['status']}")
    print("\nHUMAN APPROVAL DEMONSTRATION")
    proposal = create_followup_proposal("CVE-2021-44228", "Request analyst review of synthetic asset AST-004")
    print("Proposal:", proposal["event_id"])
    print("Status:", proposal["status"])
    decision = decide_proposal(proposal["event_id"], "APPROVE")
    print("Decision:", decision["decision"])
    print("Execution:", decision["execution_status"])
    print("\nSTAGE 4 DEMONSTRATION COMPLETED")
