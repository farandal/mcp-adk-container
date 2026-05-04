FROM python:3.11-slim

WORKDIR /app

# Install pip dependencies — MCP server + ML model requirements
COPY mcp-adk-container-1/requirements.txt .
RUN pip install --no-cache-dir --progress-bar off -r requirements.txt

# Make HF cache explicit/persistent in image and disable xet backend.
ENV HF_HOME=/app/.cache/huggingface
ENV HUGGINGFACE_HUB_CACHE=/app/.cache/huggingface/hub
ENV HF_HUB_DISABLE_XET=1
ENV HF_HUB_ENABLE_HF_TRANSFER=0

# Copy MCP server source
COPY mcp-adk-container-1/src ./src

# Copy the fraud_model package (CLIP embedder + FAISS scorer) and pre-built artifacts
# Build context must be the ANALYSISARMY parent directory (see docker-compose.yml)
COPY csirt-img-ml-model/fraud_model ./fraud_model

ENV PORT=3000
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1

EXPOSE 3000

CMD ["python", "-m", "src.server"]
