FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    git \
    && rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Copy entrypoint script
COPY docker-entrypoint.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Set entrypoint to run migrations before starting server
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

# Default command (overridden in docker-compose for dev)
# Use LOG_LEVEL environment variable to control logging verbosity
CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port 8000 --log-level $LOG_LEVEL"]
