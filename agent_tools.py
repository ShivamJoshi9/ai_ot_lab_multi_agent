import json
from agent_guardrails import check_action
from asset_analysis import analyze
from cyberintel_qa import retrieve
 
def execute_tool(action: str, argument: str) -> dict:
    """Every tool request passes through this deterministic gateway."""
    policy = check_action(action)
    if policy.decision != "ALLOW":
        return {"action": action, "status": policy.decision, "message": policy.reason, "data": None}
    try:
        if action == "search_advisory":
            records, error = retrieve(argument)
            if error:
                return {"action": action, "status": "NOT_FOUND", "message": error, "data": []}
            return {
                "action": action, "status": "SUCCESS", "message": f"Retrieved {len(records)} advisories.",
                "data": [{"cve": r["metadata"]["cve"], "product": r["metadata"]["product"], "source": r["metadata"]["source"], "document": r["document"]} for r in records],
            }
        if action == "analyze_assets":
            advisory, assets = analyze(argument.strip().upper())
            if advisory is None:
                return {"action": action, "status": "NOT_FOUND", "message": "CVE not found.", "data": []}
            return {"action": action, "status": "SUCCESS", "message": f"Found {len(assets)} matching assets.", "data": {"cve": advisory["cve"], "assets": assets}}
        if action == "calculate_risk":
            advisory, assets = analyze(argument.strip().upper())
            if advisory is None:
                return {"action": action, "status": "NOT_FOUND", "message": "CVE not found.", "data": None}
            matching = [a for a in assets if a["status"] in {"Potentially affected", "Product match - verify version"}]
            if not matching:
                priority = "NO MATCH IDENTIFIED"
            elif advisory["severity"] == "Critical" and any(a["criticality"] == "Critical" for a in matching):
                priority = "HIGH"
            else:
                priority = "REVIEW"
            return {"action": action, "status": "SUCCESS", "message": "Training risk classification completed.", "data": {"cve": advisory["cve"], "priority": priority, "matching_asset_count": len(matching), "note": "Illustrative investigation priority only. Not proof of exposure or compromise."}}
        if action == "generate_report":
            return {"action": action, "status": "SUCCESS", "message": "Report generation will be connected in a later stage.", "data": None}
        return {"action": action, "status": "BLOCK", "message": "No executable implementation for this action.", "data": None}
    except Exception as exc:
        return {"action": action, "status": "ERROR", "message": f"{type(exc).__name__}: {exc}", "data": None}
 
if __name__ == "__main__":
    print("\nADANI CYBERINTEL AGENT TOOL TEST")
    print("=" * 65)
    for action, argument in [("search_advisory", "CVE-2021-44228"), ("analyze_assets", "CVE-2021-44228"), ("calculate_risk", "CVE-2021-44228"), ("isolate_server", "AST-004"), ("propose_followup", "Review Log4j assets")]:
        result = execute_tool(action, argument)
        print(f"\nTOOL: {action}\nSTATUS: {result['status']}\nMESSAGE: {result['message']}")
        if result["data"] is not None:
            print(json.dumps(result["data"], indent=2)[:700])
