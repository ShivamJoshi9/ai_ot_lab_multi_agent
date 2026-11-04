import json
from pathlib import Path
import chromadb
from openai import OpenAI
BASE=Path(__file__).resolve().parent
DATA=BASE/'data/advisories/advisories.json'
DB=BASE/'chroma_db'
COLLECTION='cyberintel_advisories'
MODEL='text-embedding-3-small'

def main():
    advisories=json.loads(DATA.read_text(encoding='utf-8'))
    if not advisories: raise ValueError('No advisories found')
    documents=[]; metadata=[]; ids=[]
    for a in advisories:
        documents.append(
            f"Title: {a['title']}\nCVE: {a['cve']}\nProduct: {a['product']}\n"
            f"Affected versions: {a['affected_versions']}\nSeverity: {a['severity']}\n"
            f"CVSS: {a['cvss']}\nKnown Exploited Vulnerability: {a['kev']}\n"
            f"Summary: {a['summary']}\nRecommendation: {a['recommendation']}")
        ids.append(a['id'])
        metadata.append({'cve':a['cve'],'product':a['product'],
            'severity':a['severity'],'kev':a['kev'],'source':a['source']})
    result=OpenAI().embeddings.create(model=MODEL,input=documents)
    vectors=[x.embedding for x in result.data]
    db=chromadb.PersistentClient(path=str(DB))
    col=db.get_or_create_collection(name=COLLECTION,embedding_function=None)
    col.upsert(ids=ids,documents=documents,metadatas=metadata,embeddings=vectors)
    print('CYBERINTEL INDEXING COMPLETED')
    print('Indexed advisories:',col.count())
    print('Database location:',DB)
if __name__=='__main__': main()
