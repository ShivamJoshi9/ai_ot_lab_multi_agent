from pathlib import Path
import chromadb
from openai import OpenAI
BASE=Path(__file__).resolve().parent
col=chromadb.PersistentClient(path=str(BASE/'chroma_db')).get_collection(
    'cyberintel_advisories',embedding_function=None)

def search(question,top_k=3):
    if col.count()==0: raise RuntimeError('Index is empty')
    vec=OpenAI().embeddings.create(model='text-embedding-3-small',input=[question]).data[0].embedding
    results=col.query(query_embeddings=[vec],n_results=min(top_k,col.count()),
                      include=['documents','metadatas','distances'])
    print('QUESTION:',question)
    for i,(doc,meta,dist) in enumerate(zip(results['documents'][0],
            results['metadatas'][0],results['distances'][0]),1):
        print(f'RESULT {i} | {meta["cve"]} | {meta["product"]} | distance={dist:.4f}')
        print('Source:',meta['source'])
        print('Evidence:',doc[:500])
if __name__=='__main__':
    q=input('Enter your cybersecurity question: ').strip()
    if q: search(q)
    else: print('Please enter a question.')
