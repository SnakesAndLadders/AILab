FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Pre-install Guardrails AI, guardrails-api server, and ONNX runtime during build
RUN pip install --no-cache-dir \
    "guardrails-ai>=0.5.0" \
    "guardrails-api>=0.1.0" \
    "optimum[onnxruntime]>=1.19.0" \
    "transformers>=4.40.0"

# Pre-bake the ONNX DeBERTa-v3 prompt-injection model into the image layer (CACHED)
RUN python3 -c "from optimum.onnxruntime import ORTModelForSequenceClassification; \
    from transformers import AutoTokenizer; \
    model_id = 'protectai/deberta-v3-base-prompt-injection-v2'; \
    AutoTokenizer.from_pretrained(model_id).save_pretrained('/app/onnx_model'); \
    ORTModelForSequenceClassification.from_pretrained(model_id, export=True).save_pretrained('/app/onnx_model')"

# Install gunicorn after cached ONNX layer so rebuild takes ~3 seconds
RUN pip install --no-cache-dir gunicorn

COPY config.py /app/config.py

ENV GUARDRAILS_CONFIG=/app/config.py
EXPOSE 8000

CMD ["gunicorn", "-k", "uvicorn.workers.UvicornWorker", "--bind", "0.0.0.0:8000", "--workers", "1", "--timeout", "120", "config:app"]