import os
import uuid
import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct

app = FastAPI(title="Firewalled RAG Ingestion & Retrieval Service")

LITELLM_BASE_URL = os.getenv("LITELLM_BASE_URL", "http://192.168.1.10:4000")
LITELLM_API_KEY = os.getenv("LITELLM_API_KEY", "")
QDRANT_URL = os.getenv("QDRANT_URL", "http://qdrant:6333")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "lab_knowledge_base")
VECTOR_SIZE = 768  # Matches Gemini text-embedding-004 output dimensions

qdrant = QdrantClient(url=QDRANT_URL)


@app.on_event("startup")
def init_collection():
    if not qdrant.collection_exists(COLLECTION_NAME):
        qdrant.create_collection(
            collection_name=COLLECTION_NAME,
            vectors_config=VectorParams(size=VECTOR_SIZE, distance=Distance.COSINE),
        )


class IngestRequest(BaseModel):
    text: str
    source: str = "manual"


class QueryRequest(BaseModel):
    query: str
    top_k: int = 3


async def get_embedding(client: httpx.AsyncClient, text: str) -> list[float]:
    resp = await client.post(
        f"{LITELLM_BASE_URL}/v1/embeddings",
        headers={"Authorization": f"Bearer {LITELLM_API_KEY}"},
        json={"model": "safe-embed-default", "input": text},
        timeout=30.0,
    )
    resp.raise_for_status()
    return resp.json()["data"][0]["embedding"]


@app.post("/ingest")
async def ingest_document(req: IngestRequest):
    async with httpx.AsyncClient() as client:
        # 1. Defense against RAG Poisoning: Validate text via Server 1 Guardrails AI first
        guard_resp = await client.post(
            f"{LITELLM_BASE_URL}/guardrails/apply_guardrail",
            headers={"Authorization": f"Bearer {LITELLM_API_KEY}"},
            json={"guardrail_name": "guardrails-ai-shield", "text": req.text},
            timeout=15.0,
        )
        if guard_resp.status_code != 200:
            raise HTTPException(
                status_code=403,
                detail="RAG Poisoning Blocked: Document failed Guardrails AI inspection.",
            )

        # 2. Generate embedding via LiteLLM (also scrubbed by Presidio pre_call)
        vector = await get_embedding(client, req.text)

        # 3. Store clean vector in isolated Qdrant container
        point_id = str(uuid.uuid4())
        qdrant.upsert(
            collection_name=COLLECTION_NAME,
            points=[
                PointStruct(
                    id=point_id,
                    vector=vector,
                    payload={"text": req.text, "source": req.source},
                )
            ],
        )
        return {"status": "ingested", "id": point_id, "source": req.source}


@app.post("/query")
async def query_knowledge_base(req: QueryRequest):
    async with httpx.AsyncClient() as client:
        query_vector = await get_embedding(client, req.query)
        hits = qdrant.query_points(
            collection_name=COLLECTION_NAME,
            query=query_vector,
            limit=req.top_k,
        ).points

        results = [
            {"score": h.score, "source": h.payload.get("source"), "text": h.payload.get("text")}
            for h in hits
        ]
        return {"results": results}