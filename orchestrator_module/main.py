import base64
import email
import json
import os
import re
import shutil
import subprocess
import time
import traceback
import uuid
from email.header import decode_header

import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv
from imapclient import IMAPClient

print("Orchestrator: main.py is being executed.")
load_dotenv()
print("Orchestrator: load_dotenv() called.")

IMAP_SERVER = os.getenv('IMAP_SERVER')
IMAP_USER = os.getenv('IMAP_USER')
IMAP_PASSWORD = os.getenv('IMAP_PASSWORD')
PROCESSING_DIR_CONTAINER = "/app/processing_data"
OCR_SERVICE_URL = os.getenv('OCR_SERVICE_URL', "http://ocr_service:8000/extract_text_from_file/")
BERT_SERVICE_URL = os.getenv('BERT_SERVICE_URL', "http://bert_service:8000/classify_text/")
DIRECT_URLHAUS_API_ENDPOINT = os.getenv('DIRECT_URLHAUS_API_ENDPOINT', "https://urlhaus-api.abuse.ch/v1/url/")
INDICATOR_SERVICE_URL = os.getenv('INDICATOR_SERVICE_URL', "http://indicator_service:8000/extract_indicators/")
FEEDBACK_SERVICE_URL = os.getenv('FEEDBACK_SERVICE_URL', "http://feedback_service:8000/send_feedback/")
USER_AGENT_API_CALLS = os.getenv('USER_AGENT_API_CALLS', 'PhishingAnalyzerTool/1.0 (contact@example.com)')

VT_API_KEY = os.getenv('VT_API_KEY')
VIRUSTOTAL_API_URL_BASE = "https://www.virustotal.com/api/v3/urls"

print(f"Orchestrator: IMAP_SERVER: {IMAP_SERVER}")
print(f"Orchestrator: VirusTotal API Key present: {'Yes' if VT_API_KEY else 'No'}")


def decode_subject(subject_header):
    decoded_parts = decode_header(subject_header)
    subject_str = ""
    for part, charset in decoded_parts:
        if isinstance(part, bytes):
            subject_str += part.decode(charset or 'utf-8', 'ignore')
        else:
            subject_str += part
    return subject_str


def scan_file_with_clamav(filepath_in_orchestrator_container, email_processing_id_for_clamav):
    print(f"Orchestrator: Starting ClamAV scan for: {filepath_in_orchestrator_container}")
    path_relative_to_processing_dir = os.path.relpath(filepath_in_orchestrator_container, PROCESSING_DIR_CONTAINER)
    filepath_in_clamav_container = os.path.join("/scandir", path_relative_to_processing_dir)
    print(f"Orchestrator: ClamAV will scan file at path: {filepath_in_clamav_container}")
    try:
        result = subprocess.run(
            ["docker", "exec", "clamav_instance", "clamscan", "--infected", "--no-summary",
             filepath_in_clamav_container],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0:
            # ClamAV result: "Clean" - Kept in German for consistency.
            return {"infected": False, "details": "Sauber"}
        elif result.returncode == 1:
            return {"infected": True, "details": result.stdout.strip()}
        else:
            # Scan error prefix "Scan-Fehler:" - Kept in German for consistency.
            return {"infected": None, "details": f"Scan-Fehler: {result.stderr.strip()} (Code: {result.returncode})"}
    except subprocess.TimeoutExpired:
        print(f"Orchestrator: Timeout during ClamAV scan for {filepath_in_orchestrator_container}")
        return {"infected": None, "details": "ClamAV Timeout"}
    except FileNotFoundError:
        print(f"Orchestrator: Docker command not found for ClamAV.")
        return {"infected": None, "details": "Docker command not found"}
    except Exception as e:
        print(f"Orchestrator: Exception error during ClamAV scan for {filepath_in_orchestrator_container}: {e}")
        # Execution error prefix "Ausführungsfehler:" - Kept in German for consistency.
        return {"infected": None, "details": f"Ausführungsfehler: {str(e)}"}


def call_ocr_service(attachment_path):
    print(f"Orchestrator: Sending file {os.path.basename(attachment_path)} to OCR service.")
    try:
        with open(attachment_path, 'rb') as f:
            files = {'file': (os.path.basename(attachment_path), f)}
            response = requests.post(OCR_SERVICE_URL, files=files, timeout=180)
        response.raise_for_status()
        ocr_result = response.json()
        print(f"Orchestrator: OCR response for {os.path.basename(attachment_path)} received.")
        return ocr_result.get('ocr_text', '')
    except requests.exceptions.RequestException as e:
        print(f"Orchestrator: Error OCR service for {os.path.basename(attachment_path)}: {e}")
        # Error message prefix from OCR service: "OCR-API-Fehler:" - Kept in German.
        return f"OCR-API-Fehler: {str(e)}"
    except Exception as e:
        print(f"Orchestrator: Unexpected error OCR response for {os.path.basename(attachment_path)}: {e}")
        # Error message prefix from OCR service: "OCR-Verarbeitungsfehler:" - Kept in German.
        return f"OCR-Verarbeitungsfehler: {str(e)}"


def call_bert_service(text_to_classify):
    print(
        f"Orchestrator: Sending text to BERT service (Length: {len(text_to_classify)}, first 60 chars): '{text_to_classify[:60]}...'")
    if not text_to_classify or not text_to_classify.strip():
        print("Orchestrator: Empty text to BERT service, will be treated as legitimate.")
        return {"label": 0, "score": 0.0, "info": "Empty text"}
    try:
        payload = {"text": text_to_classify}
        response = requests.post(BERT_SERVICE_URL, json=payload, timeout=60)
        response.raise_for_status()
        bert_result = response.json()
        print(
            f"Orchestrator: BERT response: Label {bert_result.get('label')}, Score {bert_result.get('score', 0.0):.4f}")
        return {"label": bert_result.get('label', -1), "score": bert_result.get('score', 0.0)}
    except requests.exceptions.RequestException as e:
        print(f"Orchestrator: Error BERT service: {e}")
        # Error message prefix for BERT API: "BERT-API-Fehler:" - Kept in German for consistency.
        return {"label": -1, "score": 0.0, "error": f"BERT-API-Fehler: {str(e)}"}
    except Exception as e:
        print(f"Orchestrator: Unexpected error BERT response: {e}")
        # Error message prefix for BERT processing: "BERT-Verarbeitungsfehler:" - Kept in German for consistency.
        return {"label": -1, "score": 0.0, "error": f"BERT-Verarbeitungsfehler: {str(e)}"}


def get_email_body_and_clean(email_message_obj):
    plain_text_body = None
    html_body_str = None
    embedded_images = []
    image_parts_by_cid = {}

    print("Orchestrator: Starte Body-Extraktion...")

    # Priorisiere HTML, wenn vorhanden, sonst Plain-Text
    # Sammle zuerst alle relevanten Teile
    for part in email_message_obj.walk():
        ctype = part.get_content_type()
        cdispo = str(part.get("Content-Disposition"))

        if "attachment" in cdispo:
            continue

        content_id = part.get("Content-ID")
        if content_id:
            clean_cid = content_id.strip().strip('<>')
            if part.get_content_maintype() == 'image':
                image_parts_by_cid[clean_cid] = part
                print(f"Orchestrator: Eingebettetes Bild mit CID '{clean_cid}' registriert.")

        if ctype == 'text/html' and not html_body_str:  # Nimm den ersten HTML-Teil
            try:
                payload = part.get_payload(decode=True)
                charset = part.get_content_charset() or 'utf-8'
                html_body_str = payload.decode(charset, 'ignore')
                print(f"Orchestrator: HTML-Body gefunden (Länge roh: {len(html_body_str)}).")
            except Exception as e_html:
                print(f"Orchestrator: Fehler Dekodierung HTML-Body: {e_html}")

        elif ctype == 'text/plain' and not plain_text_body:  # Nimm den ersten Plain-Text-Teil
            try:
                payload = part.get_payload(decode=True)
                charset = part.get_content_charset() or 'utf-8'
                plain_text_body = payload.decode(charset, 'ignore')
                print(f"Orchestrator: Plain-Text-Body gefunden (Länge roh: {len(plain_text_body)}).")
            except Exception as e_text:
                print(f"Orchestrator: Fehler Dekodierung Plain-Text-Body: {e_text}")

    final_body_text = ""
    if html_body_str:
        print("Orchestrator: Verarbeite HTML-Body für Text und eingebettete Bilder.")
        soup = BeautifulSoup(html_body_str, "html.parser")

        for img_tag in soup.find_all('img'):
            src = img_tag.get('src')
            alt_text = img_tag.get('alt', '')  # Hole auch alt-Text, falls vorhanden
            img_placeholder = f" [Bild: {img_tag.get('name', alt_text or 'eingebettet')} wurde hier angezeigt] "

            if src and src.startswith('data:image'):
                try:
                    header, encoded_data = src.split(',', 1)
                    image_data_bytes = base64.b64decode(encoded_data)
                    content_type = header.split(';')[0].split(':')[1]
                    extension = content_type.split('/')[1] if '/' in content_type else 'bin'
                    filename = f"embedded_b64_{uuid.uuid4().hex[:8]}.{extension}"
                    embedded_images.append(
                        {"filename": filename, "content_type": content_type, "data": image_data_bytes})
                    print(f"Orchestrator: Base64-kodiertes Bild '{filename}' aus HTML extrahiert.")
                    img_tag.replace_with(img_placeholder)
                except Exception as e_b64:
                    print(f"Orchestrator: Fehler beim Extrahieren/Dekodieren von Base64-Bild: {e_b64}")
                    if img_tag.parent: img_tag.replace_with(f" [Fehlerhaftes eingebettetes Bild: {alt_text}] ")
            elif src and src.startswith('cid:'):
                cid = src[4:]
                if cid in image_parts_by_cid:
                    image_part = image_parts_by_cid[cid]
                    try:
                        image_data_bytes = image_part.get_payload(decode=True)
                        content_type = image_part.get_content_type()
                        filename_from_part = image_part.get_filename()
                        if not filename_from_part:
                            extension = content_type.split('/')[1] if '/' in content_type else 'bin'
                            filename_from_part = f"embedded_cid_{cid.replace('@', '_')}.{extension}"

                        embedded_images.append(
                            {"filename": filename_from_part, "content_type": content_type, "data": image_data_bytes})
                        print(
                            f"Orchestrator: CID-referenziertes Bild '{filename_from_part}' aus E-Mail-Teil extrahiert.")
                        img_tag.replace_with(f" [Bild: {filename_from_part} wurde hier angezeigt] ")
                    except Exception as e_cid:
                        print(f"Orchestrator: Fehler beim Extrahieren von CID-Bild '{cid}': {e_cid}")
                        if img_tag.parent: img_tag.replace_with(f" [Fehlerhaftes CID-Bild: {alt_text}] ")
                else:
                    print(f"Orchestrator: CID '{cid}' im HTML gefunden, aber kein passender Bild-Teil in der E-Mail.")
                    if img_tag.parent: img_tag.replace_with(
                        f" [Bild mit CID: {cid} konnte nicht geladen werden, Alt: {alt_text}] ")
            elif alt_text:  # Wenn img-Tag keinen src hat, aber alt-text
                img_tag.replace_with(f" [Bildbeschreibung: {alt_text}] ")
            elif img_tag.parent:  # Wenn img-Tag gar keine Infos hat, aber existiert
                img_tag.decompose()  # Entferne leere img-Tags ohne sie durch Text zu ersetzen

        # Verschiedene Methoden, um Text aus HTML zu extrahieren, falls soup.get_text() leer ist
        final_body_text = soup.get_text(separator=" ", strip=True)
        if not final_body_text.strip():
            print("Orchestrator: soup.get_text() lieferte leeren String, versuche andere Methoden.")
            # Entferne Skripte und Styles, die stören könnten
            for script_or_style in soup(["script", "style"]):
                script_or_style.decompose()

            # Iteriere über sichtbare Textelemente
            text_parts = []
            for element in soup.find_all(string=True):
                if element.parent.name not in ['style', 'script', 'head', 'title', 'meta', '[document]']:
                    stripped_element = element.strip()
                    if stripped_element:
                        text_parts.append(stripped_element)
            final_body_text = " ".join(text_parts)
            if final_body_text.strip():
                print("Orchestrator: Text aus HTML durch Iteration extrahiert.")

    elif plain_text_body:
        print("Orchestrator: Verwende Plain-Text-Body, da kein HTML-Body vorhanden oder HTML-Extraktion fehlschlug.")
        final_body_text = plain_text_body
    else:
        print("Orchestrator: Konnte keinen textuellen E-Mail-Body (weder HTML noch Plain) extrahieren.")
        final_body_text = ""

    cleaned_text = re.sub(r'\s+', ' ', final_body_text).strip()
    if cleaned_text:
        print(
            f"Orchestrator: E-Mail-Textkörper final bereinigt (Länge: {len(cleaned_text)}). Erste 100 Z: '{cleaned_text[:100]}'")
    else:
        print("Orchestrator: Kein finaler Textkörper nach Bereinigung.")

    return {"cleaned_text_body": cleaned_text, "embedded_images_data": embedded_images}


def extract_urls_from_text(text_content):
    if not text_content:
        print("Orchestrator: No text provided for URL extraction.")
        return []
    print(f"Orchestrator: Original text for URL extraction (first 300 chars): {text_content[:300]}")
    normalized_text = text_content.replace('\n', ' ').replace('\r', ' ')
    normalized_text = re.sub(r'\s+', ' ', normalized_text).strip()
    print(f"Orchestrator: Text after basic normalization (first 300 chars): {normalized_text[:300]}")
    rejoined_text_v1 = re.sub(r'(?<=[a-zA-Z0-9\-.])\s+/\s*(?=[a-zA-Z0-9\-_~:/?#\[\]@!$&\'()*+,;=.%])', '/',
                              normalized_text)
    if rejoined_text_v1 != normalized_text:
        print(f"Orchestrator: Text after URL repair V1 (first 300 chars): {rejoined_text_v1[:300]}")
        normalized_text = rejoined_text_v1
    rejoined_text_v2 = re.sub(r'(?<=[a-zA-Z0-9\-.])\s+\?\s*(?=[a-zA-Z0-9\-_~:/?#\[\]@!$&\'()*+,;=.%])', '?',
                              normalized_text)
    if rejoined_text_v2 != normalized_text:
        print(f"Orchestrator: Text after URL repair V2 (first 300 chars): {rejoined_text_v2[:300]}")
        normalized_text = rejoined_text_v2
    url_pattern = re.compile(
        r'((?:https?://|ftp://|file://|www\d{0,3}[.]|[a-z0-9.\-]+[.][a-z]{2,4}/)[^\s()<>"\'“”‘’;,]*(?:[^\s`!()\[\]{};:\'".,<>?«»“”‘’\s]))',
        re.IGNORECASE
    )
    found_urls_raw = url_pattern.findall(normalized_text)
    print(f"Orchestrator: Raw findings from url_pattern.findall: {found_urls_raw}")
    processed_urls = set()
    for url_string in found_urls_raw:
        url_to_process = url_string.strip()
        url_to_process = re.sub(r'[.,;:!?\)\]>]+$', '', url_to_process)
        if not re.match(r'^[a-zA-Z]+://', url_to_process):
            if url_to_process.startswith('www.') or \
                    (re.search(r'^[a-z0-9.\-]+\.[a-z]{2,}/?', url_to_process)):
                url_to_process = 'http://' + url_to_process
            else:
                print(f"Orchestrator: Discarding candidate without schema: '{url_to_process}'")
                continue
        try:
            from urllib.parse import urlparse, urlunparse
            parsed = urlparse(url_to_process.lower())
            path = re.sub(r'/+', '/', parsed.path)
            if path != '/' and path.endswith('/'): path = path[:-1]
            if not path and url_to_process.lower().endswith(parsed.netloc): path = ''
            processed_url = urlunparse(
                (parsed.scheme.lower(), parsed.netloc.lower(), path, parsed.params, parsed.query, ''))
            if processed_url: processed_urls.add(processed_url)
        except ImportError:
            processed_urls.add(url_to_process.lower().strip().rstrip('/'))
        except Exception as e_url_norm:
            print(f"Orchestrator: Error during URL normalization for '{url_to_process}': {e_url_norm}")
            processed_urls.add(url_to_process.lower().strip().rstrip('/'))
    extracted_urls = list(filter(None, processed_urls))
    if extracted_urls:
        print(f"Orchestrator: {len(extracted_urls)} final extracted URLs: {extracted_urls}")
    else:
        print("Orchestrator: No final URLs found in text.")
    return extracted_urls


def check_urls_via_direct_urlhaus_api(urls):
    url_analysis_results = []
    if not urls:
        print("Orchestrator: No URLs to send to direct URLhaus API.")
        return url_analysis_results
    print(f"Orchestrator: Sending {len(urls)} URLs individually to direct URLhaus API.")
    headers = {'User-Agent': USER_AGENT_API_CALLS}
    for url_to_check in urls:
        single_url_result = {"url": url_to_check, "is_malicious": False, "source": "urlhaus_direct",
                             "details": "Not checked or error"}
        try:
            print(f"Orchestrator: Querying direct URLhaus API for URL: {url_to_check}")
            payload = {'url': url_to_check}
            response = requests.post(DIRECT_URLHAUS_API_ENDPOINT, data=payload, headers=headers, timeout=30)
            api_response = response.json()
            print(f"Orchestrator: URLhaus API response for {url_to_check}: {api_response}")
            query_status = api_response.get("query_status")
            if query_status == "ok":
                single_url_result["is_malicious"] = True
                single_url_result["details"] = api_response
            elif query_status in ["no_results", "invalid_url"]:
                single_url_result["is_malicious"] = False
                single_url_result["details"] = api_response
                if query_status == "invalid_url": print(f"Orchestrator: URLhaus reports invalid URL: {url_to_check}")
            else:
                single_url_result["is_malicious"] = False
                single_url_result["details"] = api_response
                print(f"Orchestrator: Unexpected query_status from URLhaus: {query_status} for {url_to_check}")
        except requests.exceptions.RequestException as e_req:
            print(f"Orchestrator: Error with direct URLhaus API for {url_to_check}: {e_req}")
            # "URLhaus API connection error" - Kept in German for consistency.
            single_url_result["details"] = f"URLhaus-API-Verbindungsfehler: {str(e_req)}"
        except json.JSONDecodeError as e_json:
            print(
                f"Orchestrator: Error JSON parsing URLhaus for {url_to_check}: {e_json}. Response: {getattr(response, 'text', 'No text in response')[:200]}")
            # "URLhaus JSON parse error" - Kept in German for consistency.
            single_url_result["details"] = f"URLhaus-JSON-Parse-Fehler: {str(e_json)}"
        except Exception as e_gen:
            print(f"Orchestrator: Unexpected error URLhaus API for {url_to_check}: {e_gen}")
            # "URLhaus general error" - Kept in German for consistency.
            single_url_result["details"] = f"URLhaus-Allgemeinfehler: {str(e_gen)}"
        url_analysis_results.append(single_url_result)
    print(f"Orchestrator: Direct URLhaus API processing completed.")
    return url_analysis_results


def get_url_id_for_virustotal(url):
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def check_urls_via_virustotal(urls):
    vt_results = []
    if not VT_API_KEY:
        print("Orchestrator: VirusTotal API Key not configured. Skipping VT check.")
        return vt_results
    if not urls:
        print("Orchestrator: No URLs to send to VirusTotal.")
        return vt_results

    print(f"Orchestrator: Sending {len(urls)} URLs individually to VirusTotal API.")
    headers = {"x-apikey": VT_API_KEY, "User-Agent": USER_AGENT_API_CALLS}

    for url_to_check in urls:
        single_url_result = {"url": url_to_check, "is_malicious": False, "source": "virustotal",
                             "details": "Not checked or error"}
        # Short pause between VT requests to respect the free API limit (4 requests/minute)
        if urls.index(url_to_check) > 0:  # Not before the first request
            print("Orchestrator: Short pause (16s) before next VirusTotal request.")
            time.sleep(16)  # 60s / 4 = 15s per request, +1s buffer

        try:
            url_id = get_url_id_for_virustotal(url_to_check)
            vt_url_report_endpoint = f"{VIRUSTOTAL_API_URL_BASE}/{url_id}"

            print(f"Orchestrator: Querying VirusTotal API for URL ID: {url_id} (URL: {url_to_check})")
            response = requests.get(vt_url_report_endpoint, headers=headers, timeout=45)  # Timeout increased

            if response.status_code == 429:
                print(
                    f"Orchestrator: VirusTotal API rate limit reached. Aborting further VT requests for this run.")
                single_url_result["details"] = "API rate limit reached"
                vt_results.append(single_url_result)
                break

            response.raise_for_status()
            api_response = response.json()
            print(
                f"Orchestrator: VirusTotal API response for {url_to_check} (stats): {api_response.get('data', {}).get('attributes', {}).get('last_analysis_stats')}")

            stats = api_response.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            malicious_count = stats.get("malicious", 0)
            suspicious_count = stats.get("suspicious", 0)

            # Threshold for VirusTotal: More than 2 'malicious' or (more than 0 'malicious' AND more than 1 'suspicious')
            if malicious_count > 2 or (malicious_count > 0 and suspicious_count > 1):
                single_url_result["is_malicious"] = True
            single_url_result["details"] = api_response.get("data", {}).get("attributes", {})  # Store more details

        except requests.exceptions.HTTPError as http_err:
            if http_err.response.status_code == 404:
                print(f"Orchestrator: URL {url_to_check} (ID: {url_id}) not found in VirusTotal.")
                single_url_result["details"] = {"query_status": "not_found_in_vt"}
            else:
                print(f"Orchestrator: HTTP Error VirusTotal API for {url_to_check}: {http_err}")
                # "VirusTotal API HTTP error" - Kept in German for consistency.
                single_url_result["details"] = f"VirusTotal API HTTP-Fehler: {str(http_err)}"
        except requests.exceptions.RequestException as e_req:
            print(f"Orchestrator: Error with VirusTotal API for {url_to_check}: {e_req}")
            # "VirusTotal API connection error" - Kept in German for consistency.
            single_url_result["details"] = f"VirusTotal-API-Verbindungsfehler: {str(e_req)}"
        except Exception as e_gen:
            print(f"Orchestrator: Unexpected error VirusTotal API for {url_to_check}: {e_gen}")
            # "VirusTotal general error" - Kept in German for consistency.
            single_url_result["details"] = f"VirusTotal-Allgemeinfehler: {str(e_gen)}"
        vt_results.append(single_url_result)

    print(f"Orchestrator: VirusTotal API processing completed.")
    return vt_results


def call_indicator_service(text, context):
    print(f"Orchestrator: Sending text to Indicator service (Length: {len(text)}, first 60 chars): '{text[:60]}...'")
    if not text or not text.strip():
        print("Orchestrator: Empty text to Indicator service, no action.")
        # "Empty text for indicator extraction." - This is a specific status message.
        return {"indicators": ["Empty text for indicator extraction."], "error": "Empty text",
                "label": "not_applicable"}
    try:
        payload = {"text": text, "analysis_context": context}
        response = requests.post(INDICATOR_SERVICE_URL, json=payload, timeout=300)
        response.raise_for_status()
        indicator_result = response.json()
        print(f"Orchestrator: Indicator service response: {indicator_result}")
        return indicator_result
    except requests.exceptions.RequestException as e:
        print(f"Orchestrator: Error Indicator service: {e}")
        # Error message prefix for Indicator API: "Indicator-API-Fehler:" - Kept in German.
        return {"indicators": [], "error": f"Indicator-API-Fehler: {str(e)}", "label": "error_api"}
    except Exception as e:
        print(f"Orchestrator: Unexpected error Indicator response: {e}")
        # Error message prefix for Indicator processing: "Indicator-Verarbeitungsfehler:" - Kept in German.
        return {"indicators": [], "error": f"Indicator-Verarbeitungsfehler: {str(e)}", "label": "error_processing"}


def call_feedback_service(recipient_email, analysis_data_dict):
    print(f"Orchestrator: Sending analysis results to Feedback service for recipient: {recipient_email}")
    try:
        payload = {"recipient_email": recipient_email, "analysis_results": analysis_data_dict}
        response = requests.post(FEEDBACK_SERVICE_URL, json=payload, timeout=60)
        response.raise_for_status()
        feedback_response = response.json()
        print(f"Orchestrator: Feedback service response: {feedback_response.get('status')}")
        # "Feedback sent" - This string is from the feedback service, might be checked. Kept.
        return feedback_response.get("status") == "Feedback gesendet"
    except requests.exceptions.RequestException as e:
        print(f"Orchestrator: Error calling Feedback service: {e}")
        return False
    except Exception as e:
        print(f"Orchestrator: Unexpected error with Feedback service response: {e}")
        return False


def fetch_unread_emails():
    print("Orchestrator: fetch_unread_emails() function started.")
    loop_count = 0
    required_env_vars = {
        "IMAP Server": IMAP_SERVER, "IMAP User": IMAP_USER, "IMAP Password": IMAP_PASSWORD,
        "OCR Service URL": OCR_SERVICE_URL, "BERT Service URL": BERT_SERVICE_URL,
        "Indicator Service URL": INDICATOR_SERVICE_URL, "Feedback Service URL": FEEDBACK_SERVICE_URL
    }
    missing_vars = [name for name, var in required_env_vars.items() if not var]
    if missing_vars:
        print(
            f"Orchestrator: Critical error - Following base configuration variables are missing: {', '.join(missing_vars)}. Please check .env.")
        return
    if not DIRECT_URLHAUS_API_ENDPOINT:
        print(
            "Orchestrator: Note - DIRECT_URLHAUS_API_ENDPOINT not set, URLHaus check will not function optimally.")
    if not VT_API_KEY:
        print("Orchestrator: Note - VT_API_KEY missing, VirusTotal check will be skipped.")

    while True:
        loop_count += 1
        print(f"Orchestrator: Starting main loop iteration #{loop_count}")
        processed_email_in_loop = False
        try:
            print(f"Orchestrator: Attempting connection to IMAP {IMAP_SERVER} as {IMAP_USER}")
            with IMAPClient(IMAP_SERVER) as client:
                client.login(IMAP_USER, IMAP_PASSWORD)
                client.select_folder('INBOX')
                print(f"Orchestrator: Connected to {IMAP_SERVER}. Monitoring INBOX.")
                unseen_messages = client.search(['UNSEEN'])
                if unseen_messages:
                    print(f"Orchestrator: {len(unseen_messages)} new email(s) found.")
                    for uid, message_data in client.fetch(unseen_messages,
                                                          ['RFC822', 'INTERNALDATE', 'ENVELOPE']).items():
                        processed_email_in_loop = True
                        if not message_data:
                            print(f"Orchestrator: No message data received for UID {uid}, skipping.")
                            continue
                        raw_email_bytes = message_data.get(b'RFC822')
                        envelope = message_data.get(b'ENVELOPE')

                        if not raw_email_bytes or not envelope:
                            print(f"Orchestrator: Incomplete message data for UID {uid}, skipping.")
                            continue
                        # "Kein Betreff" - Default subject, kept in German.
                        email_subject_bytes = getattr(envelope, 'subject', b'Kein Betreff')
                        email_subject = decode_subject(email_subject_bytes.decode('utf-8', 'ignore'))
                        # "Unbekannter Absender" - Default sender, kept in German.
                        original_sender = "Unbekannter Absender"
                        if envelope.from_ and envelope.from_[0]:
                            from_obj = envelope.from_[0]
                            sender_mailbox = getattr(from_obj, 'mailbox', b'').decode('utf-8', 'ignore')
                            sender_host = getattr(from_obj, 'host', b'').decode('utf-8', 'ignore')
                            if sender_mailbox and sender_host:
                                original_sender = f"{sender_mailbox}@{sender_host}"
                            elif sender_mailbox:
                                original_sender = sender_mailbox
                        else:
                            from_header = email.message_from_bytes(raw_email_bytes)['From']
                            if from_header:
                                from_tuple = email.utils.parseaddr(from_header)
                                if from_tuple[1]:
                                    original_sender = from_tuple[1]
                                elif from_tuple[0]:
                                    original_sender = from_tuple[0]

                        print(f"Orchestrator: Processing UID {uid}, Subject '{email_subject}', From {original_sender}")

                        email_processing_id = f"email_{uid}_{int(time.time())}"
                        current_email_dir = os.path.join(PROCESSING_DIR_CONTAINER, email_processing_id)
                        attachments_dir = os.path.join(current_email_dir, "attachments")
                        embedded_images_storage_dir = os.path.join(current_email_dir, "embedded_body_images")

                        os.makedirs(attachments_dir, exist_ok=True)
                        os.makedirs(embedded_images_storage_dir, exist_ok=True)

                        raw_eml_path = os.path.join(current_email_dir, "original_email.eml")
                        with open(raw_eml_path, "wb") as f:
                            f.write(raw_email_bytes)
                        print(f"Orchestrator: UID {uid} saved: {raw_eml_path}")
                        email_message_obj = email.message_from_bytes(raw_email_bytes)

                        current_email_analysis_data = {
                            "uid": str(uid), "subject": email_subject, "sender": original_sender,
                            "email_body_cleaned": None, "body_bert_classification": None,
                            "attachments_analysis": [], "url_analysis": [],
                            "fine_tuned_llama_assessment": None
                        }

                        body_extraction_result = get_email_body_and_clean(email_message_obj)
                        cleaned_body = body_extraction_result.get("cleaned_text_body", "")
                        embedded_images_data_list = body_extraction_result.get("embedded_images_data", [])
                        current_email_analysis_data["email_body_cleaned"] = cleaned_body

                        text_for_indicator_extraction = cleaned_body if cleaned_body else ""
                        # "No body or error" - This info string is specific.
                        body_bert_result = {"label": 0, "score": 0.0, "info": "No body or error"}
                        if cleaned_body:
                            body_bert_result = call_bert_service(cleaned_body)
                        current_email_analysis_data["body_bert_classification"] = body_bert_result

                        all_urls_in_email = set(extract_urls_from_text(cleaned_body))

                        # Capture if there is any preliminary suspicion from BERT or ClamAV.
                        # This information can serve as context for the Llama model.
                        preliminary_suspicion_for_llama_context = body_bert_result.get("label") == 1

                        if embedded_images_data_list:
                            print(
                                f"Orchestrator: Processing {len(embedded_images_data_list)} embedded image(s) from email body.")
                            for idx, img_info in enumerate(embedded_images_data_list):
                                img_filename = img_info.get("filename", f"embedded_img_{idx + 1}.bin")
                                img_data_bytes = img_info.get("data")
                                if not img_data_bytes: continue
                                img_path = os.path.join(embedded_images_storage_dir, img_filename)
                                emb_img_analysis_data = {
                                    "filename": img_filename, "type": "embedded_in_body",
                                    "path_in_orchestrator": img_path,
                                    "clamav_infected": None, "clamav_details": "Not scanned",
                                    "ocr_text": None, "bert_ocr_classification": None
                                }
                                try:
                                    with open(img_path, "wb") as f_img:
                                        f_img.write(img_data_bytes)
                                    print(f"Orchestrator: Embedded image '{img_filename}' saved: {img_path}")
                                    clam_res_emb = scan_file_with_clamav(img_path, email_processing_id)
                                    emb_img_analysis_data["clamav_infected"] = clam_res_emb["infected"]
                                    emb_img_analysis_data["clamav_details"] = clam_res_emb["details"]
                                    if clam_res_emb["infected"] is True: preliminary_suspicion_for_llama_context = True
                                    if clam_res_emb["infected"] is False:
                                        print(f"Orchestrator: Starting OCR for embedded image '{img_filename}'")
                                        ocr_txt_emb = call_ocr_service(img_path)
                                        emb_img_analysis_data["ocr_text"] = ocr_txt_emb
                                        if ocr_txt_emb and not any(err_str in ocr_txt_emb for err_str in
                                                                   ["OCR-API-Fehler",  # German error string
                                                                    "OCR-Verarbeitungsfehler"]) and len(
                                            # German error string
                                            ocr_txt_emb.strip()) > 0:
                                            text_for_indicator_extraction += f"\n\n--- Text from embedded image: {img_filename} ---\n{ocr_txt_emb}\n--- End text from embedded image ---"
                                            urls_from_emb_ocr = extract_urls_from_text(ocr_txt_emb)
                                            all_urls_in_email.update(urls_from_emb_ocr)
                                            bert_ocr_res_emb = call_bert_service(ocr_txt_emb)
                                            emb_img_analysis_data["bert_ocr_classification"] = bert_ocr_res_emb
                                            if bert_ocr_res_emb.get(
                                                    "label") == 1: preliminary_suspicion_for_llama_context = True
                                except Exception as e_emb_img_proc:
                                    print(
                                        f"Orchestrator: Error processing embedded image '{img_filename}': {e_emb_img_proc}")
                                    # "Error during image processing" - Kept in German for consistency.
                                    emb_img_analysis_data[
                                        "clamav_details"] = f"Fehler bei Bildverarbeitung: {str(e_emb_img_proc)}"
                                current_email_analysis_data["attachments_analysis"].append(emb_img_analysis_data)

                        for part in email_message_obj.walk():
                            content_disposition = part.get("Content-Disposition")
                            filename = part.get_filename()
                            content_id = part.get("Content-ID")
                            is_real_attachment = (content_disposition and "attachment" in content_disposition) or \
                                                 (filename and not content_id and part.get_content_maintype() != 'text')
                            if is_real_attachment and filename:
                                decoded_filename = "".join(
                                    p.decode(c or 'utf-8', 'ignore') if isinstance(p, bytes) else p
                                    for p, c in decode_header(filename)
                                )
                                is_already_processed_embedded = False
                                for emb_res in current_email_analysis_data["attachments_analysis"]:
                                    if emb_res.get("type") == "embedded_in_body" and emb_res[
                                        "filename"] == decoded_filename:
                                        is_already_processed_embedded = True;
                                        break
                                if is_already_processed_embedded:
                                    print(
                                        f"Orchestrator: Attachment '{decoded_filename}' was already processed as embedded image, skipping re-analysis.")
                                    continue
                                attachment_path = os.path.join(attachments_dir, decoded_filename)
                                att_data = {"filename": decoded_filename, "type": "attachment",
                                            "path_in_orchestrator": attachment_path,
                                            "clamav_infected": None, "clamav_details": "Not scanned",
                                            "ocr_text": None, "bert_ocr_classification": None}
                                try:
                                    with open(attachment_path, "wb") as f_attach:
                                        f_attach.write(part.get_payload(decode=True))
                                    print(
                                        f"Orchestrator: Regular attachment '{decoded_filename}' extracted to {attachment_path}")
                                    clam_res = scan_file_with_clamav(attachment_path, email_processing_id)
                                    att_data["clamav_infected"] = clam_res["infected"]
                                    att_data["clamav_details"] = clam_res["details"]
                                    if clam_res["infected"] is True: preliminary_suspicion_for_llama_context = True
                                    if clam_res["infected"] is False:
                                        if os.path.splitext(decoded_filename)[1].lower() in ['.pdf', '.png', '.jpg',
                                                                                             '.jpeg', '.tiff', '.bmp',
                                                                                             '.gif']:
                                            ocr_txt = call_ocr_service(attachment_path)
                                            att_data["ocr_text"] = ocr_txt
                                            if ocr_txt and not any(err_str in ocr_txt for err_str in
                                                                   ["OCR-API-Fehler",  # German error string
                                                                    "OCR-Verarbeitungsfehler"]) and len(
                                                # German error string
                                                ocr_txt.strip()) > 0:
                                                text_for_indicator_extraction += f"\n\n--- Text from attachment start: {decoded_filename} ---\n{ocr_txt}\n--- Text from attachment end: {decoded_filename} ---"
                                                urls_from_ocr = extract_urls_from_text(ocr_txt)
                                                all_urls_in_email.update(urls_from_ocr)
                                                ocr_bert_res = call_bert_service(ocr_txt)
                                                att_data["bert_ocr_classification"] = ocr_bert_res
                                                if ocr_bert_res.get(
                                                        "label") == 1: preliminary_suspicion_for_llama_context = True
                                except Exception as e_att_proc:
                                    print(f"Orchestrator: Error with attachment '{decoded_filename}': {e_att_proc}")
                                current_email_analysis_data["attachments_analysis"].append(att_data)

                        unique_urls_list = list(all_urls_in_email)
                        combined_url_analysis_results = []
                        if unique_urls_list:
                            # Google Safe Browse no longer called directly
                            # if GOOGLE_SB_API_KEY:
                            # google_sb_results = check_urls_via_google_safe_Browse(unique_urls_list)
                            # if google_sb_results: combined_url_analysis_results.extend(google_sb_results)

                            urlhaus_results = check_urls_via_direct_urlhaus_api(unique_urls_list)
                            if urlhaus_results: combined_url_analysis_results.extend(urlhaus_results)

                            if VT_API_KEY:
                                virustotal_results = check_urls_via_virustotal(unique_urls_list)
                                if virustotal_results: combined_url_analysis_results.extend(virustotal_results)

                            current_email_analysis_data["url_analysis"] = combined_url_analysis_results
                            for res in combined_url_analysis_results:
                                if res.get("is_malicious"):
                                    preliminary_suspicion_for_llama_context = True
                                    break
                        else:
                            print("Orchestrator: No URLs found for external checking.")

                        is_text_meaningful_for_llama = False
                        current_text_for_llama = text_for_indicator_extraction.strip()
                        if current_text_for_llama:
                            placeholder_pattern = r"^\[PastedGraphic-\d+\.(png|jpeg|jpg|gif)\]$"
                            if not re.match(placeholder_pattern, current_text_for_llama, re.IGNORECASE) and len(
                                    current_text_for_llama) > 10:
                                is_text_meaningful_for_llama = True
                            else:
                                print(
                                    f"Orchestrator: Text '{current_text_for_llama[:60]}...' is only a placeholder or too short for Llama.")

                        if is_text_meaningful_for_llama:
                            print(
                                f"Orchestrator: Meaningful text present (Length {len(current_text_for_llama)}). Starting Llama analysis (preliminary suspicion: {preliminary_suspicion_for_llama_context}).")
                            indicator_context = {
                                "body_bert_classification": current_email_analysis_data["body_bert_classification"],
                                "url_analysis": current_email_analysis_data["url_analysis"],
                                "attachments_analysis": [
                                    {
                                        "filename": att.get("filename"),
                                        "clamav_infected": att.get("clamav_infected"),
                                        "bert_ocr_classification": att.get("bert_ocr_classification")
                                    } for att in current_email_analysis_data["attachments_analysis"]
                                ],
                                "preliminary_suspicion_based_on_other_tools": preliminary_suspicion_for_llama_context
                            }
                            extracted_indicators_result = call_indicator_service(current_text_for_llama,
                                                                                 indicator_context)
                            current_email_analysis_data["fine_tuned_llama_assessment"] = extracted_indicators_result
                        else:
                            print("Orchestrator: No meaningful text available for Llama analysis.")
                            # "Not performed (no meaningful text)." - Llama fallback, kept in German.
                            current_email_analysis_data["fine_tuned_llama_assessment"] = {
                                "label": "not_run_no_meaningful_text",
                                "indicators": ["Nicht durchgeführt (kein aussagekräftiger Text)."]}

                        print(f"Orchestrator: FINAL ANALYSIS RESULTS for email UID {uid}:")
                        try:
                            print(json.dumps(current_email_analysis_data, indent=2, ensure_ascii=False))
                        except Exception as e_json_dump:
                            print(f"Orchestrator: Error during json.dumps: {e_json_dump}")
                            print(str(current_email_analysis_data))
                        # "Unbekannter Absender" - Default sender, kept in German.
                        if original_sender != "Unbekannter Absender" and "@" in original_sender:
                            feedback_sent = call_feedback_service(original_sender, current_email_analysis_data)
                            if feedback_sent:
                                print(
                                    f"Orchestrator: Feedback email for UID {uid} to {original_sender} reported as successfully sent.")
                            else:
                                print(
                                    f"Orchestrator: Feedback email for UID {uid} to {original_sender} error/not sent.")
                        else:
                            print(
                                f"Orchestrator: No valid recipient ({original_sender}) for feedback of UID {uid}.")

                        print(f"Orchestrator: Processing of UID {uid} completed.")
                        client.add_flags(uid, [b'\\Seen'])
                        print(f"Orchestrator: Email UID {uid} marked as read.")
                        try:
                            shutil.rmtree(current_email_dir)
                            print(f"Orchestrator: Temporary data for UID {uid} at {current_email_dir} deleted.")
                        except Exception as e_del:
                            print(f"Orchestrator: Error deleting {current_email_dir}: {e_del}")
                else:
                    print("Orchestrator: No new emails.")
                client.logout()
                print(f"Orchestrator: Logged out from IMAP server {IMAP_SERVER}.")
        except IMAPClient.Error as e_imap:
            print(f"Orchestrator: IMAP error in main try block: {e_imap}")
            traceback.print_exc()
        except requests.exceptions.ConnectionError as e_conn:
            print(f"Orchestrator: Service connection error in main try block: {e_conn}.")
            traceback.print_exc()
        except Exception as e_main:
            print(f"Orchestrator: General error in main try block for loop #{loop_count}: {e_main}")
            traceback.print_exc()
        if not processed_email_in_loop and loop_count > 1:
            print(f"Orchestrator: End of loop #{loop_count} (no emails processed). Waiting 60 sec.")
            time.sleep(60)
        elif processed_email_in_loop:
            print(f"Orchestrator: End of loop #{loop_count} (emails processed). Next check shortly.")
            time.sleep(10)
        else:  # First loop, no emails
            print(f"Orchestrator: End of loop #{loop_count}. Waiting 60 sec.")
            time.sleep(60)


if __name__ == "__main__":
    print("Orchestrator: Script __main__ is being executed.")
    required_core_vars = [IMAP_SERVER, IMAP_USER, IMAP_PASSWORD, OCR_SERVICE_URL, BERT_SERVICE_URL,
                          INDICATOR_SERVICE_URL, FEEDBACK_SERVICE_URL]
    if not all(required_core_vars):
        print(
            "Orchestrator: Critical error - Base configuration variables missing (IMAP or Service URLs). Please check .env.")
    else:
        if not DIRECT_URLHAUS_API_ENDPOINT:
            print(
                "Orchestrator: Note - DIRECT_URLHAUS_API_ENDPOINT not set, URLHaus check will not function optimally.")
        if not VT_API_KEY:
            print("Orchestrator: Note - VT_API_KEY missing, VirusTotal check will be skipped.")
        fetch_unread_emails()
