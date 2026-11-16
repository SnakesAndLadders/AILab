FROM python:3.11-slim

WORKDIR /app

# Install Guardrails AI + lightweight CPU ONNX Runtime (avoids heavy CUDA/PyTorch bloat)
RUN pip install --no-cache-dir \
    guardrails-ai \
    fastapi \
    uvicorn \
    regex \
    "optimum[onnxruntime]" \
    transformers

# Pre-bake the DeBERTa prompt-injection classifier into /app/onnx_model at build time
RUN python -c "from optimum.onnxruntime import ORTModelForSequenceClassification; \
    from transformers import AutoTokenizer; \
    model_id = 'protectai/deberta-v3-base-prompt-injection-v2'; \
    tokenizer = AutoTokenizer.from_pretrained(model_id); \
    model = ORTModelForSequenceClassification.from_pretrained(model_id, export=True); \
    tokenizer.save_pretrained('/app/onnx_model'); \
    model.save_pretrained('/app/onnx_model')"

COPY config.py /app/config.py

EXPOSE 8000
CMD ["guardrails", "start", "--config", "/app/config.py", "--port", "8000"]
