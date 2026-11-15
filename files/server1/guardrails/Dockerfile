FROM python:3.11-slim

WORKDIR /app
RUN pip install --no-cache-dir \
    guardrails-ai \
    fastapi \
    uvicorn \
    regex

COPY config.py /app/config.py

EXPOSE 8000
CMD ["guardrails", "start", "--config", "/app/config.py", "--port", "8000"]
