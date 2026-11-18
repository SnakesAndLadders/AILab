import os
import uuid
import httpx
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from qdrant_client import QdrantClient
from qdrant_client.models import Distance, VectorParams, PointStruct

app = FastAPI(title="Firewalled RAG Ingestion & Retrieval Service")

LITELLM_URL = os.getenv("LITELLM_BASE_URL", os.getenv("OPENAI_BASE_URL", "http://192.168.1.10:4000")).replace("/v1", "")

LITELLM_API_KEY = os.getenv("LITELLM_API_KEY", "")
QDRANT_URL = os.getenv("QDRANT_URL", "http://qdrant:6333")
COLLECTION_NAME = os.getenv("COLLECTION_NAME", "lab_knowledge_base")
VECTOR_SIZE = 768

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
    return resp.json()["data"]["embedding"]


@app.post("/ingest")
async def validate_with_guardrails(text: str) -> None:
    """Validate text against Server 1's pre_call Guardrails AI shield before embedding."""
    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(
            f"{LITELLM_URL}/v1/chat/completions",
            headers={"Authorization": f"Bearer {LITELLM_API_KEY}"},
            json={
                "model": "safe-chat-default",
                "messages": [{"role": "user", "content": text}],
                "max_tokens": 1,
            },
        )
        if resp.status_code != 200:
            raise HTTPException(
                status_code=400,
                detail=f"Blocked by Guardrails AI Shield: {resp.text}",
            )



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
