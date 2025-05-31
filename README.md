Dieses Repository enthält den Prototyp eines Systems zur automatisierten Erkennung und Analyse von Phishing-E-Mails,
entwickelt im Rahmen einer Masterarbeit.

## Beschreibung

Das System überwacht ein IMAP-Postfach auf neue E-Mails, extrahiert Textinhalte (inklusive OCR für Bilder/PDFs und
QR-Code-Dekodierung) sowie Anhänge und URLs. Diese Komponenten werden dann durch verschiedene Analysemodule bewertet:

* **ClamAV**: Scannt Anhänge auf bekannte Malware.
* **URLAnalyse**: Überprüft URLs gegen eine Datenbank bekannter bösartiger URLs.
* **BERT-Modell**: Klassifiziert E-Mail-Texte (Body und OCR-Texte) als Phishing oder legitim (fine-tuned Modell:
  `[AndyAT/German Phishing Detection](https://huggingface.co/collections/AndyAT/german-phishing-detection-682dd1442d6040a2d13aebbb)`).
* **Indicator-Modell (GGUF)**: Extrahiert spezifische Phishing-Indikatoren aus verdächtigen Texten und liefert eine
  Gesamtklassifikation ausgeführt über einen `llama-cpp-python` Server).

Die gesammelten Analyseergebnisse werden aufbereitet und als Bericht per E-Mail an den ursprünglichen Einsender
zurückgemeldet.

## Technologie-Stack

* Python
* Docker & Docker Compose
* FastAPI (für die API-basierten Analysemodule)
* IMAPClient (E-Mail-Empfang)
* smtplib (E-Mail-Versand)
* Hugging Face Transformers, llama-cpp-python
* Tesseract OCR, Pyzbar (QR-Codes)
* ClamAV
* URLhaus & VirusTotal API

## Setup und Ausführung

### Voraussetzungen

* Docker
* Docker Compose
* Git

### Schritte

1. **Repository klonen:**
   ```bash
   git clone [https://github.com/andischweig/GermanPhishingDetection.git](https://github.com/andischweig/GermanPhishingDetection.git) 
   cd GermanPhishingDetection
   ```
2. **Modell-Datei vorbereiten:**
    * Lade die GGUF-Datei vom Hugging Face Repository `<HF_PFAD>/<VERWENDETES_INDICATOR_MODELL>` herunter.
    * Erstelle im Projekt-Hauptverzeichnis einen Ordner namens `llm_models`.
    * Platziere die heruntergeladene GGUF-Datei in diesem Ordner: `models/<VERWENDETES_INDICATOR_MODELL>.gguf`.

3. **Konfigurationsdatei `.env` erstellen:**
    * Kopiere die Vorlagedatei `.env.example` zu `.env`:
        ```bash
        cp .env.example .env
        ```
    * Öffne die `.env`-Datei und trage deine eigenen Zugangsdaten und Konfigurationen ein (IMAP-Zugang, SMTP-Zugang,
      Hugging Face Token, Modellnamen etc.).

4. **Docker Container bauen und starten:**
   ```bash
   docker-compose up --build -d
   ```
   Der erste Start kann länger dauern, da die Docker-Images gebaut und Modelle (BERT von Hugging Face, Llama GGUF wird
   vom `llamacpp_server` beim ersten Start geladen) heruntergeladen werden müssen.

## Verwendung

1. Sende eine E-Mail an die in der `.env`-Datei konfigurierte IMAP-Adresse (`IMAP_USER`).
2. Das System analysiert die E-Mail automatisch.
3. Nach Abschluss der Analyse erhält der ursprüngliche Absender der Test-E-Mail einen Bericht per E-Mail.
4. Die Logs der Docker-Container können mit `docker-compose logs -f` oder für einzelne Dienste (z.B.
   `docker-compose logs -f orchestrator`) eingesehen werden.

## Struktur des Projekts

* `orchestrator_module/`: Zentrales Steuermodul.
* `ocr_module/`: Dienst für Texterkennung und QR-Code-Dekodierung.
* `bert_module/`: Dienst für die Phishing-Klassifikation mit BERT.
* `indicator_module/`: Dienst (API-Client), der mit dem `llamacpp_server` für die Indikatorenextraktion kommuniziert.
* `feedback_module/`: Dienst zur Erstellung und zum Versand der Feedback-E-Mails.
* `docker-compose.yml`: Definiert alle Dienste und deren Zusammenspiel.
* `llm_models/`: Lokales Verzeichnis für GGUF-Modelle (wird in den `llamacpp_server`-Container gemountet).
