FROM python:3.11-slim
RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

COPY app.py .
COPY templates/ templates/
COPY static/ static/
COPY public/ public/

RUN mkdir -p /app/logs && \
    chmod 755 /app/logs && \
    touch /app/telosmiligramme.log && \
    chmod 666 /app/telosmiligramme.log

RUN useradd --create-home --shell /bin/bash app && \
    chown -R app:app /app
USER app

EXPOSE 8080

ENV BACKEND_PORT=8080
ENV FLASK_ENV=production

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/ || exit 1

CMD ["python", "app.py"]
