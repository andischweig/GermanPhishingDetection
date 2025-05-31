import json
import os
import traceback

import requests

# --- Global Configuration Variables ---
# Base URL for the Llama.cpp server's API endpoint.
# Initialized by `initialize_llamacpp_client_config()`.
LLAMACPP_SERVER_ENDPOINT_BASE = None

# Name of the model to be used for API calls to the Llama.cpp server.
# Initialized by `initialize_llamacpp_client_config()`.
MODEL_NAME_FOR_API_CALL = None


def initialize_llamacpp_client_config():
    """
    Initializes global configuration variables for the Llama.cpp client
    by retrieving settings from environment variables.
    """
    global LLAMACPP_SERVER_ENDPOINT_BASE, MODEL_NAME_FOR_API_CALL

    # Retrieve the Llama.cpp server URL from an environment variable.
    # Defaults to "http://llamacpp_server:8000" if the variable is not set.
    LLAMACPP_SERVER_ENDPOINT_BASE = os.getenv(
        "INDICATOR_LLAMACPP_SERVER_URL", "http://llamacpp_server:8000"
    )
    # Retrieve the model name to be used in API calls from an environment variable.
    MODEL_NAME_FOR_API_CALL = os.getenv("MODEL_NAME_FOR_LLAMACPP_API")

    if not LLAMACPP_SERVER_ENDPOINT_BASE:
        print("IndicatorExtractor: ERROR - INDICATOR_LLAMACPP_SERVER_URL not set in .env.")
        return False
    if not MODEL_NAME_FOR_API_CALL:
        print("IndicatorExtractor: ERROR - MODEL_NAME_FOR_LLAMACPP_API not set in .env.")
        return False

    print(
        f"IndicatorExtractor: Configured for Llama.cpp Server: "
        f"Endpoint base '{LLAMACPP_SERVER_ENDPOINT_BASE}', "
        f"Model for API '{MODEL_NAME_FOR_API_CALL}'"
    )
    return True


def generate_chat_messages_for_fine_tuned_model(email_text_input: str) -> list:
    """
    Generates the list of messages to be sent to the Llama.cpp chat completions API,
    including a system message that provides instructions to the model and a user
    message containing the email text to be analyzed.

    Args:
        email_text_input: The raw text content of the email.

    Returns:
        A list of message dictionaries for the API.
    """
    # INFO: The following system prompt was translated from German. Ensure model compatibility with the English version.
    # The system message guides the model's behavior, instructing it on the expected classification task
    # and the desired JSON output format.
    # This message is crucial for the model to understand how to process the input and what output format to use.
    system_message_content = (
        "Du bist ein Cybersicherheitssystem. Analysiere den folgenden E-Mail-Inhalt. "
        "Klassifiziere ihn als legitimate', 'maybe_phishing', oder 'phishing'."
        "Gib die Klassifizierung und, falls zutreffend (für 'phishing' oder 'maybe_phishing'), "
        "eine Liste von Indikatoren in deutscher Sprache, die auf Phishing hinweisen, als JSON-Objekt mit den Schlüsseln "
        "'label' und 'indicators' zurück. Stelle sicher, dass deine Ausgabe immer ein valides JSON-Objekt ist, "
        'das der Struktur {"label": "deine_Klassifizierung", "indicators": ["Indikator1", "Indikator2", ...]} '
        'oder {"label": "legitimate", "indicators": []} entspricht.'
    )

    # The user message contains the actual email text that the model needs to analyze.
    messages = [
        {"role": "system", "content": system_message_content},
        {"role": "user", "content": email_text_input}
    ]
    print(f"IndicatorExtractor: Chat messages generated for Llama.cpp Server.")
    return messages


def extract_indicators_from_llamacpp_server(email_text: str, analysis_context: dict = None) -> dict:
    """
    Extracts phishing indicators from email text using a Llama.cpp server.

    Args:
        email_text: The text content of the email to analyze.
        analysis_context: Optional dictionary for future use or context passing.

    Returns:
        A dictionary containing the 'label' (e.g., 'phishing', 'legitimate') and
        a list of 'indicators'. Returns an error structure on failure.
    """
    # Check if the Llama.cpp server client configuration has been initialized.
    if not LLAMACPP_SERVER_ENDPOINT_BASE or not MODEL_NAME_FOR_API_CALL:
        print("IndicatorExtractor: Llama.cpp Server configuration not initialized.")
        # Return an error dictionary if configuration is missing.
        return {"error": "Llama.cpp Server configuration missing", "label": "error_config", "indicators": []}

    chat_messages = generate_chat_messages_for_fine_tuned_model(email_text)

    # Construct the full API endpoint for chat completions.
    api_endpoint = f"{LLAMACPP_SERVER_ENDPOINT_BASE}/v1/chat/completions"

    # Define the payload for the API request.
    payload = {
        "model": MODEL_NAME_FOR_API_CALL,  # Specifies which model to use on the server.
        "messages": chat_messages,  # The chat history, including system and user messages.
        "temperature": 0.1,  # Low temperature for more deterministic, less creative output.
        "max_tokens": 512,  # Maximum number of tokens to generate in the response.
        "response_format": {"type": "json_object"}  # Enforces JSON output from the model.
    }
    print(f"IndicatorExtractor: Sending request to Llama.cpp Server: {api_endpoint}")
    print(f"IndicatorExtractor: Payload (excerpt): model='{payload['model']}', temp={payload['temperature']}")

    try:
        # Send the POST request to the Llama.cpp server.
        # timeout=300 seconds (5 minutes) for the request to complete.
        response = requests.post(api_endpoint, json=payload, timeout=300)
        # Raise an HTTPError for bad responses (4XX or 5XX).
        response.raise_for_status()

        api_response_json = response.json()
        print(f"IndicatorExtractor: Response from Llama.cpp Server:\n{json.dumps(api_response_json, indent=2)}")

        # Extract the model's generated content from the API response.
        # The content is expected within response.choices[0].message.content.
        extracted_json_str = None
        if (
                "choices" in api_response_json and
                isinstance(api_response_json["choices"], list) and
                len(api_response_json["choices"]) > 0 and
                "message" in api_response_json["choices"][0] and
                "content" in api_response_json["choices"][0]["message"]
        ):
            extracted_json_str = api_response_json["choices"][0]["message"]["content"].strip()
        else:
            # Handle unexpected API response structure.
            print(f"IndicatorExtractor: Unexpected response structure from Llama.cpp Server: {api_response_json}")
            return {
                "error": "Unexpected response structure from Llama.cpp Server",
                "label": "error_api_response",
                "indicators": []
            }

        print(f"IndicatorExtractor: Extracted JSON string from response:\n{extracted_json_str}")

        try:
            # Parse the extracted string (expected to be JSON) into a Python dictionary.
            parsed_json = json.loads(extracted_json_str)
            # Extract 'label' and 'indicators' from the parsed JSON.
            # Default to "unknown_label_from_model" if 'label' is missing.
            label = parsed_json.get("label", "unknown_label_from_model")
            indicators = parsed_json.get("indicators", [])
            # Ensure indicators is always a list, even if the model returns a single string.
            if not isinstance(indicators, list):
                indicators = [str(indicators)] if indicators else []
            print(f"IndicatorExtractor: JSON successfully parsed. Label: {label}, Indicators: {indicators}")
            return {"label": label, "indicators": indicators}
        except json.JSONDecodeError as e:
            # Handle errors if the model's response is not valid JSON.
            print(f"IndicatorExtractor: Error parsing JSON string from model: {e}")
            print(f"IndicatorExtractor: Received string was: {extracted_json_str}")
            return {
                "error": "JSON Decode Error",  # General error type
                "label": "error_parsing_json",  # Specific label for this error type
                "indicators": [f"Model response was not valid JSON: {extracted_json_str}"]
            }

    except requests.exceptions.RequestException as e:
        # Handle network errors or other issues during the API request.
        print(f"IndicatorExtractor: Error during request to Llama.cpp Server: {e}")
        return {
            "error": f"Llama.cpp Server API request error: {str(e)}",
            "label": "error_api",
            "indicators": []
        }
    except Exception as e:
        # Handle any other unexpected errors during the process.
        print(f"IndicatorExtractor: General error Llama.cpp Server processing: {e}")
        traceback.print_exc()  # Print full traceback for debugging.
        return {
            "error": f"General Llama.cpp Server error: {str(e)}",
            "label": "error_general",
            "indicators": []
        }
