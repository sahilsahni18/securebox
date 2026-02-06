FROM python:3.10-slim
WORKDIR /app
# Install system dependencies including PostgreSQL client libraries
RUN apt-get update && apt-get install -y \
    gcc \
    curl \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
# Create non-root user
RUN useradd --create-home --shell /bin/bash app \
    && chown -R app:app /app
USER app
EXPOSE 8002
CMD ["gunicorn", "--bind", "0.0.0.0:8002", "--workers", "4", "--timeout", "120", "app:app"]
