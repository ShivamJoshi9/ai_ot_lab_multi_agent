import csv,json,re
from pathlib import Path
BASE=Path(__file__).resolve().parent

def load_data():
    with (BASE/'data/advisories/advisories.json').open(encoding='utf-8') as f: adv=json.load(f)
    with (BASE/'data/assets/assets.csv').open(newline='',encoding='utf-8') as f: assets=list(csv.DictReader(f))
    return adv,assets

def normalize_product(s): return ' '.join(s.lower().strip().split())

def log4j_version_status(version):
    m=re.fullmatch(r'(\d+)\.(\d+)\.(\d+)',version.strip())
    if not m: return 'Version verification required'
    major,minor,patch=map(int,m.groups())
    if major==2 and (minor,patch)<=(14,1): return 'Potentially affected'
    if major==2 and (minor,patch)>(14,1): return 'Outside supplied affected range'
    return 'Version verification required'

def classify_asset(asset,advisory):
    if normalize_product(asset['product'])!=normalize_product(advisory['product']):
        return 'No matching product'
    if advisory['cve']=='CVE-2021-44228':
        return log4j_version_status(asset['version'])
    return 'Product match - verify version'

def analyze(cve):
    advisories,assets=load_data()
    advisory=next((a for a in advisories if a['cve']==cve.upper()),None)
    if advisory is None: return None,[]
    results=[]
    for asset in assets:
        status=classify_asset(asset,advisory)
        if status=='No matching product': continue
        results.append({
            'asset_id':asset['asset_id'],'asset_name':asset['asset_name'],
            'product':asset['product'],'version':asset['version'],
            'criticality':asset['criticality'],'status':status})
    return advisory,results

if __name__=='__main__':
    print('ADANI CYBERINTEL | Synthetic training data only')
    cve=input('Enter CVE identifier: ').strip().upper()
    advisory,results=analyze(cve)
    if advisory is None: print('CVE not found in local knowledge base.')
    else:
        print('CVE:',advisory['cve'],'|',advisory['title'])
        if not results: print('No matching products; this does not prove no exposure.')
        for a in results:
            print(a['asset_id'],a['asset_name'],a['product'],a['version'],a['status'])
        print('Verification required; not a finding of confirmed compromise.')
