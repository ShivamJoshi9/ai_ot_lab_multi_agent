import json
import re
from pathlib import Path
import gradio as gr
import pandas as pd
from agent_workflow import run_investigation
from agent_approval import demonstrate_guardrail, create_followup_proposal, decide_proposal
from asset_analysis import analyze
 
BASE = Path(__file__).resolve().parent
AUDIT_DIR = BASE / "reports" / "agent_audit"
CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.I)
MATCH_COLUMNS = ["Asset ID", "Asset Name", "Product", "Version", "Criticality", "Status"]
CSS = """
.gradio-container {max-width: 1380px !important; margin: auto !important;
font-family: Inter, Arial, sans-serif !important;}
#hero {background: linear-gradient(120deg, #0B1930, #16466B); border-radius: 18px;
padding: 28px 32px; margin-bottom: 16px;}
#hero h1, #hero p, #hero strong {color: #FFFFFF !important;}
#hero h1 {font-size: 30px !important; font-weight: 750 !important;}
#hero p {opacity: 0.94;}
#training-banner {background: #EDF5FA; border-left: 4px solid #1689A3;
padding: 12px 18px; border-radius: 8px;}
#training-banner p {color: #173B55 !important;}
"""
 
def safe_text(value):
    return str(value or "")
 
def format_trace(trace):
    if not trace:
        return "No agent execution recorded yet."
    lines = ["### Agent Execution Timeline"]
    for index, event in enumerate(trace, start=1):
        action = safe_text(event.get("action"))
        status = safe_text(event.get("status"))
        message = safe_text(event.get("message"))
        lines.append(f"**{index}. {event.get('event', 'EVENT')}**\n\nAction: `{action}`")
        if status:
            lines.append(f"Status: `{status}`")
        if message:
            lines.append(f"Details: {message}")
        lines.append("---")
    return "\n\n".join(lines)
 
def investigate(request):
    if not request or not request.strip():
        return "Please enter an investigation request.", "No execution trace.", "No observations."
    try:
        result = run_investigation(request)
        details = [{"action": item.get("action"), "status": item.get("status"), "message": item.get("message"), "data": item.get("data")} for item in result.get("observations", [])]
        return safe_text(result.get("final_answer")), format_trace(result.get("trace", [])), json.dumps(details, indent=2, ensure_ascii=False, default=str)
    except Exception as exc:
        print("Agent investigation error:", repr(exc))
        return "Investigation failed. Check the terminal logs.", "Execution could not be completed.", "No observations available."
 
def asset_intelligence(cve):
    cve = safe_text(cve).strip().upper()
    if not CVE_PATTERN.fullmatch(cve):
        return "Enter a valid CVE identifier.", pd.DataFrame(columns=MATCH_COLUMNS)
    advisory, assets = analyze(cve)
    if advisory is None:
        return "CVE not found in the local training knowledge base.", pd.DataFrame(columns=MATCH_COLUMNS)
    rows = [{"Asset ID": a["asset_id"], "Asset Name": a["asset_name"], "Product": a["product"], "Version": a["version"], "Criticality": a["criticality"], "Status": a["status"]} for a in assets]
    summary = (f"### {advisory['cve']}\n\n**{advisory['title']}**\n\nSeverity: **{advisory['severity']}**\n\nMatching products: **{len(assets)}**\n\nResults are preliminary training classifications. Confirm exact versions and deployment conditions before drawing exposure conclusions.")
    return summary, pd.DataFrame(rows, columns=MATCH_COLUMNS)
 
def guardrail_test(action, argument):
    result, event = demonstrate_guardrail(action, safe_text(argument))
    message = (f"### Guardrail Decision: {result['status']}\n\n**Requested action:** `{action}`\n\n**Reason:** {result['message']}\n\n**Audit event:** `{event['event_id']}`\n\n**Execution scope:** Synthetic training only.")
    return message, json.dumps(event, indent=2, ensure_ascii=False)
 
def create_proposal(cve, description):
    cve = safe_text(cve).strip().upper()
    if not CVE_PATTERN.fullmatch(cve):
        return "Invalid CVE identifier.", ""
    try:
        proposal = create_followup_proposal(cve, safe_text(description))
        return f"Proposal created: {proposal['event_id']}\nStatus: PENDING", proposal["event_id"]
    except Exception as exc:
        return f"Unable to create proposal: {exc}", ""
 
def review_proposal(proposal_id, decision):
    if not proposal_id:
        return "Create a proposal first."
    try:
        result = decide_proposal(proposal_id, decision)
        return f"Decision: {result['decision']}\nExecution: {result['execution_status']}\nAudit event: {result['event_id']}"
    except Exception as exc:
        return f"Review failed: {exc}"
 
def audit_table():
    rows = []
    for path in sorted(AUDIT_DIR.glob("*.json"), reverse=True)[:100]:
        try:
            item = json.loads(path.read_text(encoding="utf-8"))
            rows.append({"Timestamp": item.get("timestamp_utc", ""), "Event": item.get("event_type", ""), "Action": item.get("action", ""), "Decision": item.get("decision", item.get("status", "")), "Event ID": item.get("event_id", "")})
        except (OSError, ValueError):
            continue
    return pd.DataFrame(rows, columns=["Timestamp", "Event", "Action", "Decision", "Event ID"])
 
with gr.Blocks(title="Adani CyberIntel Agentic Investigation Workbench", css=CSS) as demo:
    gr.Markdown("""# ADANI CYBERINTEL
### AGENTIC INVESTIGATION WORKBENCH
**LangGraph | AI Tool Calling | Human Approval | Deterministic Guardrails**
Intelligent investigation of public cybersecurity advisories against a synthetic enterprise asset inventory.""", elem_id="hero")
    gr.Markdown("**TRAINING ENVIRONMENT** | Public and synthetic data only. No live SOC connectivity, autonomous remediation or real infrastructure modification.", elem_id="training-banner")
    with gr.Tabs():
        with gr.Tab("Mission Control"):
            gr.Markdown("## AI Investigation Console")
            request = gr.Textbox(label="Investigation request", value="Investigate CVE-2021-44228. Find relevant advisories, identify potentially affected synthetic assets and assess investigation priority.", lines=3)
            run_button = gr.Button("Run AI Investigation", variant="primary")
            final_answer = gr.Markdown()
            gr.Markdown("### Investigation Observations")
            observations = gr.Code(language="json", label="Tool observations")
            with gr.Accordion("Agent Execution Timeline", open=True):
                trace = gr.Markdown()
            run_button.click(fn=investigate, inputs=request, outputs=[final_answer, trace, observations])
        with gr.Tab("Evidence & Assets"):
            gr.Markdown("## Synthetic Asset Intelligence")
            asset_cve = gr.Textbox(label="CVE identifier", value="CVE-2021-44228")
            asset_button = gr.Button("Analyze Synthetic Assets", variant="primary")
            asset_summary = gr.Markdown()
            asset_results = gr.Dataframe(headers=MATCH_COLUMNS, interactive=False, label="Matching assets")
            asset_button.click(fn=asset_intelligence, inputs=asset_cve, outputs=[asset_summary, asset_results])
        with gr.Tab("Human Approval"):
            gr.Markdown("## Human-in-the-Loop Approval Centre")
            gr.Markdown("Create a simulated follow-up recommendation. An analyst may approve or reject it. **No real action is executed.**")
            proposal_cve = gr.Textbox(label="CVE identifier", value="CVE-2021-44228")
            proposal_description = gr.Textbox(label="Follow-up recommendation", value="Request analyst verification of synthetic asset AST-004.", lines=2)
            proposal_button = gr.Button("Create Review Proposal", variant="primary")
            proposal_status = gr.Textbox(label="Proposal status", interactive=False)
            proposal_id = gr.Textbox(label="Proposal ID", interactive=False)
            proposal_button.click(fn=create_proposal, inputs=[proposal_cve, proposal_description], outputs=[proposal_status, proposal_id])
            decision = gr.Radio(choices=["APPROVE", "REJECT"], value="REJECT", label="Human decision")
            review_button = gr.Button("Record Human Decision")
            review_result = gr.Textbox(label="Review result", interactive=False)
            review_button.click(fn=review_proposal, inputs=[proposal_id, decision], outputs=review_result)
        with gr.Tab("Guardrail Monitor"):
            gr.Markdown("## Agent Action Authorization")
            gr.Markdown("This demonstration sends an action through the same deterministic gateway used by the investigation agent.")
            action = gr.Dropdown(choices=["search_advisory", "analyze_assets", "calculate_risk", "propose_followup", "isolate_server", "delete_logs", "modify_firewall", "unknown_tool"], value="isolate_server", label="Requested action")
            argument = gr.Textbox(label="Tool argument", value="AST-004")
            guardrail_button = gr.Button("Test Guardrail", variant="primary")
            guardrail_result = gr.Markdown()
            guardrail_audit = gr.Code(language="json", label="Audit record")
            guardrail_button.click(fn=guardrail_test, inputs=[action, argument], outputs=[guardrail_result, guardrail_audit])
        with gr.Tab("Audit Centre"):
            gr.Markdown("## Training Audit Records")
            gr.Markdown("View recent guardrail tests and human approval decisions.")
            refresh_button = gr.Button("Refresh Audit Records")
            audit_results = gr.Dataframe(value=audit_table(), interactive=False, label="Recent audit events")
            refresh_button.click(fn=audit_table, outputs=audit_results)
    gr.Markdown("---\n**Adani AI, Generative AI & Agentic AI Workshop**\n\nEducational prototype using public advisories and fictional enterprise assets. All follow-up actions are simulated.")
 
demo.launch(server_name="0.0.0.0", server_port=7863, share=False, show_error=False)
