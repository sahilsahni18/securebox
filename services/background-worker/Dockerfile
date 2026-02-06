FROM python:3.10-slim
WORKDIR /app
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY . .
RUN useradd --create-home --shell /bin/bash app \
    && chown -R app:app /app
USER app
# Run Celery worker
CMD ["celery", "-A", "worker.celery_app", "worker", "--loglevel=info"]
