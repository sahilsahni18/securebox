
# Start from Python 3.10 slim image (smaller size)
FROM python:3.10-slim
# Set working directory inside container
WORKDIR /app
# Install system dependencies
# Why gcc? Some Python packages need C compiler
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    && rm -rf /var/lib/apt/lists/*
# Copy requirements first (Docker layer caching optimization)
# Why separate? If requirements don't change, Docker reuses this layer
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# Copy application code
COPY . .
# Create non-root user (security best practice)
# Why? If container is compromised, attacker has limited privileges
RUN useradd --create-home --shell /bin/bash app \
    && chown -R app:app /app
USER app
# Expose port 8001
EXPOSE 8001
# Run the application
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "4"]
# Why 4 workers? Balances load and resource usage for typical deployments
