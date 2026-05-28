FROM python:3.11-slim

# System dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libmagic1 \
    wget \
    tar \
    && rm -rf /var/lib/apt/lists/*

# Install Detect It Easy CLI (optional — gracefully falls back if absent)
RUN wget -q \
    https://github.com/horsicq/DIE-engine/releases/download/3.09/die_lin64_portable_3.09.tar.gz \
    -O /tmp/die.tar.gz \
    && mkdir -p /opt/die \
    && tar -xzf /tmp/die.tar.gz -C /opt/die --strip-components=1 \
    && ln -sf /opt/die/diec /usr/local/bin/diec \
    && rm /tmp/die.tar.gz \
    || echo "WARNING: DIE download failed — packer detection via diec disabled"

WORKDIR /app

# Install Python dependencies first (cache layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

# Ensure runtime directories exist
RUN mkdir -p data/uploads ml/models

EXPOSE 5000

ENV FLASK_APP=backend.app
ENV FLASK_ENV=production
ENV PYTHONUNBUFFERED=1

CMD ["python", "-m", "flask", "run", "--host=0.0.0.0", "--port=5000"]
