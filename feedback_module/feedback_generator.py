import os
import re
import smtplib
import traceback
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

SMTP_SERVER_FEEDBACK = os.getenv('SMTP_SERVER')
SMTP_PORT_FEEDBACK = int(os.getenv('SMTP_PORT', 587))
SMTP_USER_FEEDBACK = os.getenv('SMTP_USER')
SMTP_PASSWORD_FEEDBACK = os.getenv('SMTP_PASSWORD')

DISCLAIMER_TEXT = """
Wichtiger Hinweis: Diese Analyse wurde automatisiert erstellt und dient als erste Einschätzung. 
Kein automatisiertes System ist perfekt. Überprüfen Sie E-Mails immer mit gesundem Menschenverstand, 
besonders wenn Sie zur Eingabe von Daten oder zum Öffnen von Links/Anhängen aufgefordert werden. 
Klicken Sie nicht auf verdächtige Links und geben Sie keine persönlichen Informationen preis, 
wenn Sie sich unsicher sind. Wenden Sie sich im Zweifel direkt an den vermeintlichen Absender 
über einen Ihnen bekannten, sicheren Kontaktweg (z.B. Telefon oder offizielle Webseite).
"""


def mask_url(url_string):
    if not url_string or not isinstance(url_string, str):
        return "ungültige URL"
    try:
        masked_url = re.sub(r'^http://', 'hXXp://', url_string, flags=re.IGNORECASE)
        masked_url = re.sub(r'^https://', 'hXXps://', masked_url, flags=re.IGNORECASE)
        path_start_index = masked_url.find('/', masked_url.find('://') + 3)
        if path_start_index == -1:
            domain_part = masked_url
            path_part = ""
        else:
            domain_part = masked_url[:path_start_index]
            path_part = masked_url[path_start_index:]
        domain_part = domain_part.replace('.', '[.]')
        return domain_part + path_part
    except Exception:
        return url_string


def get_combined_text_analysis_label_for_display(analysis_results):
    fine_tuned_llama_assessment = analysis_results.get("fine_tuned_llama_assessment", {})
    llama_label_str = fine_tuned_llama_assessment.get("label", "not_run").lower()

    bert_body_label_int = analysis_results.get("body_bert_classification", {}).get("label", -1)

    bert_ocr_labels_int_list = []
    for att in analysis_results.get("attachments_analysis", []):
        bert_ocr = att.get("bert_ocr_classification")
        if bert_ocr and "label" in bert_ocr:
            bert_ocr_labels_int_list.append(bert_ocr.get("label"))

    bert_body_prio = -1
    if bert_body_label_int == 1:
        bert_body_prio = 1
    elif bert_body_label_int == 0:
        bert_body_prio = 0

    bert_ocr_prio = -1
    if 1 in bert_ocr_labels_int_list:
        bert_ocr_prio = 1
    elif 0 in bert_ocr_labels_int_list and not (1 in bert_ocr_labels_int_list):
        bert_ocr_prio = 0

    final_prio = max(bert_body_prio, bert_ocr_prio)

    if final_prio == 2: return "Als Phishing eingestuft"
    if final_prio == 1: return "Als möglicherweise Phishing eingestuft"
    if final_prio == 0: return "Als unverdächtig eingestuft"

    return "Textanalyse nicht eindeutig oder nicht durchgeführt"


def determine_overall_assessment(analysis_results):
    print(f"FeedbackGenerator: Bestimme Gesamtbewertung für UID {analysis_results.get('uid')}")

    is_clamav_positive = False
    for att in analysis_results.get("attachments_analysis", []):
        if att.get("clamav_infected") is True:
            is_clamav_positive = True
            break

    is_url_check_positive = False
    for url_res in analysis_results.get("url_analysis", []):
        if url_res.get("is_malicious") is True:
            is_url_check_positive = True
            break

    fine_tuned_llama_assessment = analysis_results.get("fine_tuned_llama_assessment", {})
    llama_label = fine_tuned_llama_assessment.get("label", "not_run").lower()
    llama_indicators = fine_tuned_llama_assessment.get("indicators", [])

    if is_clamav_positive or is_url_check_positive == "phishing":
        return "Phishing (Hoher Verdacht)"

    are_specific_llama_indicators_found = False
    if llama_indicators:
        default_negative_responses = [
            "keine spezifischen phishing-indikatoren gefunden.",
            "keine spezifischen, eindeutigen phishing-indikatoren nach kritischer prüfung gefunden.",
            "nicht durchgeführt (kein primärer phishing-verdacht).",
            "nicht durchgeführt (kein text für analyse).",
            "nicht durchgeführt (kein aussagekräftiger text für ki-analyse oder kein primärer verdacht).",
            "nicht durchgeführt (kein aussagekräftiger text für ki-analyse).",
            "ich kann diese anfrage nicht erfüllen."
        ]
        has_actual_indicator = False
        for indicator_text in llama_indicators:
            is_default_negative = False
            for neg_resp in default_negative_responses:
                if neg_resp in indicator_text.lower().strip():
                    is_default_negative = True
                    break
            if not is_default_negative and indicator_text.strip():
                has_actual_indicator = True
                break
        if has_actual_indicator:
            are_specific_llama_indicators_found = True

    bert_body_label_is_phishing = analysis_results.get("body_bert_classification", {}).get("label") == 1

    bert_ocr_label_is_phishing = False
    for att in analysis_results.get("attachments_analysis", []):
        bert_ocr = att.get("bert_ocr_classification")
        if bert_ocr and bert_ocr.get("label") == 1:
            bert_ocr_label_is_phishing = True
            break
    if bert_body_label_is_phishing or bert_ocr_label_is_phishing:
        return "Möglicherweise Phishing (Verdacht)"

    return "Kein direkter Phishing-Verdacht"


def create_feedback_email_body(analysis_results):
    print(f"FeedbackGenerator: Erstelle E-Mail-Body für UID {analysis_results.get('uid')}")

    combined_text_label_for_display = get_combined_text_analysis_label_for_display(analysis_results)
    overall_assessment = determine_overall_assessment(
        analysis_results)  # Nutzt interne Logik, nicht das Display-Label direkt

    subject = f"Analysebericht [{overall_assessment}] für Ihre E-Mail: \"{analysis_results.get('subject', 'N/A')}\""

    body = f"Sehr geehrte/r Einsender/in,\n\n"
    body += f"vielen Dank für Ihre E-Mail mit dem Betreff \"{analysis_results.get('subject', 'N/A')}\".\n"
    body += "Unsere automatische Analyse hat folgendes Ergebnis geliefert:\n\n"
    body += f"+++ GESAMTEINSCHÄTZUNG: {overall_assessment} +++\n\n"

    if "Hoher Verdacht" in overall_assessment:
        body += "ACHTUNG: Es wurden klare Anzeichen für einen Betrugsversuch oder schädliche Inhalte gefunden!\n"
        body += "Unsere Empfehlung: Löschen Sie diese E-Mail und interagieren Sie nicht mit Inhalten oder Anhängen.\n"
    elif "Möglicherweise Phishing" in overall_assessment:
        body += "VORSICHT: Einige Merkmale dieser E-Mail sind verdächtig.\n"
        body += "Unsere Empfehlung: Seien Sie besonders misstrauisch. Antworten Sie nicht direkt und geben Sie keine Daten preis.\n"
    else:
        body += "Die Analyse hat keine eindeutigen Hinweise auf einen Betrugsversuch oder schädliche Inhalte ergeben.\n"
        body += "Unsere Empfehlung: Bleiben Sie dennoch allgemein wachsam.\n"

    body += "\n--- Details der Analyse ---\n\n"
    details_generated = False

    # 1. Klassifizierung der Nachricht
    if combined_text_label_for_display not in ["Textanalyse nicht eindeutig oder nicht durchgeführt"]:
        body += f"Klassifizierung der Nachricht: {overall_assessment}.\n"
        details_generated = True

    # 2. Anhangsanalyse
    attachment_details_text = ""
    has_attachment_issues_or_info = False
    for att in analysis_results.get("attachments_analysis", []):
        att_filename = att.get('filename', 'Unbekannter Anhang')
        att_type_info = "(Eingebettet)" if att.get("type") == "embedded_in_body" else "(Als Datei)"
        line_prefix = f"  - Anhang '{att_filename}' {att_type_info}: "
        att_issues_found_this_attachment = []

        if att.get("clamav_infected") is True:
            att_issues_found_this_attachment.append("SCHADSOFTWARE gefunden!")
            has_attachment_issues_or_info = True;
            details_generated = True

        bert_ocr = att.get("bert_ocr_classification")
        if bert_ocr and bert_ocr.get("label") == 1:
            att_issues_found_this_attachment.append(f"Textinhalt als verdächtig (BERT) eingestuft.")
            has_attachment_issues_or_info = True;
            details_generated = True
        elif bert_ocr and bert_ocr.get("label") == 0 and os.path.splitext(att_filename)[1].lower() in ['.pdf', '.png',
                                                                                                       '.jpg', '.jpeg',
                                                                                                       '.tiff', '.bmp',
                                                                                                       '.gif']:
            # Nur Info für unverdächtigen OCR-Text, wenn es ein Bild/PDF war
            att_issues_found_this_attachment.append("Textinhalt als unverdächtig (BERT) eingestuft.")
            has_attachment_issues_or_info = True

        if att_issues_found_this_attachment:
            attachment_details_text += line_prefix + " ".join(att_issues_found_this_attachment) + "\n"
        elif att.get("type") == "attachment" and att.get("clamav_infected") is False:
            attachment_details_text += line_prefix + "Keine direkten Bedrohungen erkannt.\n"
            has_attachment_issues_or_info = True

    if has_attachment_issues_or_info:
        body += "\nAnhangsanalyse:\n" + attachment_details_text
    elif analysis_results.get("attachments_analysis"):
        body += "\nAnhangsanalyse: Keine Anhänge mit relevanten Analyseergebnissen oder keine Anhänge vorhanden.\n"

    # 3. URL-Analyse
    url_details_text = ""
    has_url_issues_or_info = False
    for url_res in analysis_results.get("url_analysis", []):
        url_to_display = url_res.get('url', 'Unbekannte URL')
        source = str(url_res.get("source", "Unbekannte Quelle")).replace("_direct", "").replace("_", " ").title()
        if url_res.get("is_malicious") is True:
            masked_display_url = mask_url(url_to_display)
            threat_details_parts = []
            if "urlhaus" in source.lower():
                threat_details_parts.append(
                    f"URLhaus: {url_res.get('details', {}).get('threat', 'Typ nicht spezifiziert')}")
            if "virustotal" in source.lower():
                stats = url_res.get("details", {}).get("last_analysis_stats", {})
                malicious_vt = stats.get("malicious", 0)
                total_vt = sum(
                    s for s in stats.values() if isinstance(s, int))  # Sicherstellen, dass nur Zahlen summiert werden
                threat_details_parts.append(f"VirusTotal: {malicious_vt}/{total_vt} Engines positiv")

            threat_display = "; ".join(threat_details_parts) if threat_details_parts else "Allgemein bösartig"
            url_details_text += f"  - '{masked_display_url}' als bekannt schädlich erkannt (Quelle(n): {source}, Details: {threat_display}).\n"
            has_url_issues_or_info = True;
            details_generated = True

    if has_url_issues_or_info:
        body += "\nURL-Analyse:\n"
        if url_details_text:
            body += url_details_text
        else:
            body += "  Keine der geprüften URLs wurde als bekannt schädlich eingestuft.\n"

    elif analysis_results.get("url_analysis"):
        body += "\nURL-Analyse: Keine keine Ergebnisse für die URLs verfügbar.\n"

    # 4. Von KI identifizierte verdächtige Text-Merkmale (Llama-Indikatoren)
    fine_tuned_llama_assessment = analysis_results.get("fine_tuned_llama_assessment", {})
    llama_indicators = fine_tuned_llama_assessment.get("indicators", [])
    specific_indicators_from_llama = []
    if llama_indicators:
        default_negative_responses = [
            "keine spezifischen phishing-indikatoren gefunden.",
            "keine spezifischen, eindeutigen phishing-indikatoren nach kritischer prüfung gefunden.",
            "nicht durchgeführt",
            "ich kann diese anfrage nicht erfüllen."
        ]
        specific_indicators_from_llama = [ind for ind in llama_indicators if ind.strip() and not any(
            neg_res in ind.lower().strip() for neg_res in default_negative_responses)]

        if specific_indicators_from_llama:
            body += "\nZusätzlich identifizierte verdächtige Text-Merkmale:\n"
            for indicator in specific_indicators_from_llama:
                body += f"  {indicator}\n"
            details_generated = True

    # 5. Fallback-Text
    if not details_generated and "Kein direkter Phishing-Verdacht" in overall_assessment:
        body += "Es wurden keine spezifischen technischen Alarmsignale oder verdächtigen Textmerkmale automatisch erkannt.\n"
    elif not details_generated and "Möglicherweise Phishing (Verdacht)" in overall_assessment:
        body += "Obwohl keine spezifischen technischen Details hervorgehoben werden konnten, deuten allgemeine Merkmale auf einen möglichen Betrugsversuch hin.\n"

    body += "\n" + DISCLAIMER_TEXT.strip()

    print(f"FeedbackGenerator: E-Mail-Betreff: {subject}")
    return subject, body


def send_email(recipient_email, subject, body):
    if not all([SMTP_SERVER_FEEDBACK, SMTP_USER_FEEDBACK, SMTP_PASSWORD_FEEDBACK]):
        print("FeedbackGenerator: FEHLER - SMTP-Konfiguration unvollständig. E-Mail nicht gesendet.")
        return False
    msg = MIMEMultipart()
    msg['From'] = SMTP_USER_FEEDBACK
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain', 'utf-8'))
    try:
        print(f"FeedbackGenerator: Verbinde mit SMTP Server {SMTP_SERVER_FEEDBACK}:{SMTP_PORT_FEEDBACK}")
        with smtplib.SMTP(SMTP_SERVER_FEEDBACK, SMTP_PORT_FEEDBACK) as server:
            server.ehlo();
            server.starttls();
            server.ehlo()
            server.login(SMTP_USER_FEEDBACK, SMTP_PASSWORD_FEEDBACK)
            server.sendmail(SMTP_USER_FEEDBACK, recipient_email, msg.as_string())
        print(f"FeedbackGenerator: Feedback-E-Mail erfolgreich an {recipient_email} gesendet.")
        return True
    except Exception as e:
        print(f"FeedbackGenerator: Fehler beim Senden der Feedback-E-Mail an {recipient_email}: {e}")
        traceback.print_exc()
        return False
