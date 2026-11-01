FROM python:3.13-slim

WORKDIR /app

# Optional: nmap is used automatically if present; the platform works without it.
# RUN apt-get update && apt-get install -y --no-install-recommends nmap && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./backend
COPY frontend ./frontend

ENV PTEST_ENVIRONMENT=production
EXPOSE 8000

# Run as non-root.
RUN useradd -m appuser && chown -R appuser /app
USER appuser

CMD ["uvicorn", "app.main:app", "--app-dir", "backend", "--host", "0.0.0.0", "--port", "8000"]
