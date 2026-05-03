FROM python:3.11-slim

WORKDIR /app

# Install pip dependencies — MCP server + ML model requirements
COPY mcp-adk-container-1/requirements.txt .
RUN pip install --no-cache-dir --progress-bar off -r requirements.txt

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
