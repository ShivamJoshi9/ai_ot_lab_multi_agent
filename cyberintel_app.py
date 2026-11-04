import csv,json,re
from datetime import datetime,timezone
from pathlib import Path
import gradio as gr
import pandas as pd
from cyberintel_qa import answer
from asset_analysis import analyze

BASE=Path(__file__).resolve().parent
REPORT_DIR=BASE/'reports'
REPORT_DIR.mkdir(exist_ok=True)
ADVISORIES=json.loads((BASE/'data/advisories/advisories.json').read_text(encoding='utf-8'))
with (BASE/'data/assets/assets.csv').open(newline='',encoding='utf-8') as f:
    ASSETS=list(csv.DictReader(f))
MATCH_COLUMNS=['Asset ID','Asset Name','Product','Version','Criticality','Status']

def advisory_table():
    return pd.DataFrame([{'CVE':a['cve'],'Title':a['title'],
        'Product':a['product'],'Severity':a['severity'],
        'KEV':'Yes' if a['kev'] else 'No'} for a in ADVISORIES])

def asset_table():
    return pd.DataFrame([{'Asset ID':a['asset_id'],'Asset Name':a['asset_name'],
        'Product':a['product'],'Version':a['version'],
        'Criticality':a['criticality']} for a in ASSETS])

def investigation(question):
    if not question or not question.strip(): return 'Please enter a question.','No evidence yet.'
    try:
        result,records=answer(question)
        if not records: return result,'No matching evidence returned.'
        evidence=[]
        for i,r in enumerate(records,1):
            m=r['metadata']
            evidence.append(f"### Source {i}: {m['cve']}\n"
                f"**Product:** {m['product']}\n\n**Source:** {m['source']}\n\n"
                f"```\n{r['document']}\n```")
        return result,'\n\n---\n\n'.join(evidence)
    except Exception as exc:
        print('Investigation error:',repr(exc))
        return 'Investigation failed; check terminal.','No evidence available.'

def asset_check(cve):
    if not cve or not cve.strip():
        return 'Please enter a CVE identifier.',pd.DataFrame(columns=MATCH_COLUMNS)
    cve=cve.strip().upper()
    if not re.fullmatch(r'CVE-\d{4}-\d{4,}',cve):
        return 'Invalid CVE format.',pd.DataFrame(columns=MATCH_COLUMNS)
    advisory,results=analyze(cve)
    if advisory is None:
        return 'CVE not found in local knowledge base.',pd.DataFrame(columns=MATCH_COLUMNS)
    rows=[{'Asset ID':r['asset_id'],'Asset Name':r['asset_name'],
        'Product':r['product'],'Version':r['version'],
        'Criticality':r['criticality'],'Status':r['status']} for r in results]
    summary=(f"### {advisory['cve']}\n**{advisory['title']}**\n\n"
        f"Severity: **{advisory['severity']}**\n\nMatching products: **{len(results)}**\n\n"
        'Preliminary training classifications only. Verify exact versions and vendor conditions.')
    if not results: summary+='\n\nNo matching products; this does not prove unaffected.'
    return summary,pd.DataFrame(rows,columns=MATCH_COLUMNS)

def create_report(cve):
    if not cve or not cve.strip(): return None,'Enter a CVE identifier.'
    cve=cve.strip().upper()
    if not re.fullmatch(r'CVE-\d{4}-\d{4,}',cve): return None,'Invalid CVE identifier.'
    advisory,results=analyze(cve)
    if advisory is None: return None,'CVE not found in knowledge base.'
    report={'report_type':'Adani CyberIntel Training Investigation',
        'generated_at_utc':datetime.now(timezone.utc).isoformat(),
        'training_data_only':True,'advisory':advisory,
        'matching_assets':results,'matching_asset_count':len(results),
        'disclaimer':'Fictional assets and simplified advisories; human verification required.'}
    filename=REPORT_DIR/f'investigation_{cve}.json'
    filename.write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    return str(filename),f'Report generated successfully for {cve}.'

CSS=".gradio-container {max-width:1250px !important; margin:auto !important;} #hero {background:linear-gradient(120deg,#10233f,#18466c); color:white; padding:26px; border-radius:14px;} #hero h1,#hero p {color:white !important;}"
with gr.Blocks(title='Adani CyberIntel RAG Workbench',css=CSS) as demo:
    gr.Markdown('# Adani CyberIntel RAG Workbench\n**Advanced RAG | Cybersecurity Advisory Intelligence**\n\nMulti-document retrieval, evidence-grounded analysis, synthetic asset matching and reporting.\n\n**TRAINING ENVIRONMENT | PUBLIC AND SYNTHETIC DATA ONLY**',elem_id='hero')
    gr.Markdown(f'**Knowledge base:** {len(ADVISORIES)} advisories | '
                f'**Synthetic assets:** {len(ASSETS)} | **AI:** OpenAI + ChromaDB')
    with gr.Tabs():
        with gr.Tab('Investigation'):
            gr.Markdown('### AI-Powered Cybersecurity Investigation')
            question=gr.Textbox(label='Ask a cybersecurity question',
                placeholder='Explain CVE-2021-44228 and its recommended remediation.',lines=2)
            ask=gr.Button('Investigate',variant='primary')
            response=gr.Markdown()
            with gr.Accordion('Retrieved Evidence and Citations',open=True):
                evidence=gr.Markdown()
            ask.click(investigation,inputs=question,outputs=[response,evidence])
        with gr.Tab('Asset Exposure'):
            gr.Markdown('### Synthetic Enterprise Asset Analysis')
            cve=gr.Textbox(label='Enter CVE identifier',value='CVE-2021-44228')
            check=gr.Button('Analyze Assets',variant='primary')
            summary=gr.Markdown()
            results=gr.Dataframe(headers=MATCH_COLUMNS,interactive=False,label='Matching Assets')
            check.click(asset_check,inputs=cve,outputs=[summary,results])
        with gr.Tab('Knowledge Base'):
            gr.Markdown('### Indexed Cybersecurity Advisories')
            gr.Dataframe(value=advisory_table(),interactive=False,label='Advisory Inventory')
            gr.Markdown('### Synthetic Enterprise Assets')
            gr.Dataframe(value=asset_table(),interactive=False,label='Asset Inventory')
        with gr.Tab('Reports'):
            gr.Markdown('### Download an Investigation Report')
            report_cve=gr.Textbox(label='CVE identifier',value='CVE-2021-44228')
            generate=gr.Button('Generate Report',variant='primary')
            status=gr.Textbox(label='Report status',interactive=False)
            report_file=gr.File(label='Download Investigation Report')
            generate.click(create_report,inputs=report_cve,outputs=[report_file,status])
    gr.Markdown('---\n**Adani CyberIntel Advanced RAG Workshop** | Fictional assets only; no live security integrations.')

demo.launch(server_name='0.0.0.0',server_port=7862,share=False,
            show_error=False,allowed_paths=[str(REPORT_DIR)])
