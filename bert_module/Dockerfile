FROM python:3.10-slim

WORKDIR /app

# Umgebungsvariable für den Transformers Cache (optional, aber gut für Konsistenz)
ENV TRANSFORMERS_CACHE=/app/model_cache
ENV HF_HOME=/app/model_cache

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY bert_classifier.py .
COPY main.py .

# Erstelle das Cache-Verzeichnis, falls es nicht existiert, und setze Berechtigungen
RUN mkdir -p /app/model_cache && chmod -R 777 /app/model_cache

# Standard-Port für Uvicorn
EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]