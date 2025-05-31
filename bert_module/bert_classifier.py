import os

import torch
from transformers import AutoTokenizer, AutoModelForSequenceClassification

# Global variables to store the model, tokenizer, device, and Hugging Face token.
# These are initialized by the load_model() function.

MODEL_NAME_BERT = None  # Stores the name or path of the BERT model from environment variables.
TOKENIZER_BERT = None  # Stores the tokenizer instance for the loaded BERT model.
MODEL_BERT = None  # Stores the loaded BERT sequence classification model.
DEVICE_BERT = None  # Stores the device (e.g., "cuda" or "cpu") where the model is loaded.
HF_TOKEN_BERT = None  # Stores the Hugging Face API token, used for accessing private models.


def load_model():
    """
    Loads the BERT model and tokenizer based on environment variables.
    Sets the global variables MODEL_NAME_BERT, TOKENIZER_BERT, MODEL_BERT, DEVICE_BERT, HF_TOKEN_BERT.
    """
    global MODEL_NAME_BERT, TOKENIZER_BERT, MODEL_BERT, DEVICE_BERT, HF_TOKEN_BERT

    # Retrieve the model name and Hugging Face token from environment variables.
    MODEL_NAME_BERT = os.getenv("BERT_MODEL_NAME")
    HF_TOKEN_BERT = os.getenv("HF_TOKEN")

    if not MODEL_NAME_BERT:
        print("BERT-Classifier: ERROR - BERT_MODEL_NAME not set in .env.")
        return False

    print(f"BERT-Classifier: Loading model '{MODEL_NAME_BERT}'...")
    try:
        # Load the tokenizer associated with the specified model name.
        TOKENIZER_BERT = AutoTokenizer.from_pretrained(MODEL_NAME_BERT, token=HF_TOKEN_BERT)
        # Load the sequence classification model.
        MODEL_BERT = AutoModelForSequenceClassification.from_pretrained(MODEL_NAME_BERT, token=HF_TOKEN_BERT)

        # Determine the device to use: CUDA if available, otherwise CPU.
        DEVICE_BERT = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        # Move the model to the selected device.
        MODEL_BERT.to(DEVICE_BERT)
        # Set the model to evaluation mode. This disables layers like dropout, which are used during training.
        MODEL_BERT.eval()

        print(f"BERT-Classifier: Model '{MODEL_NAME_BERT}' successfully loaded on {DEVICE_BERT}.")

        # Small warning if it's a custom model and HF_TOKEN is not explicitly provided.
        # This is a heuristic and might need adjustment based on naming conventions.
        if not HF_TOKEN_BERT and "AndyAT/" in MODEL_NAME_BERT:
            print(
                "BERT-Classifier: WARNING - HF_TOKEN not explicitly used for potentially private model. "
                "Ensure the repo is public or the token is globally available."
            )
        return True
    except Exception as e:
        print(f"BERT-Classifier: Error loading model '{MODEL_NAME_BERT}': {e}")
        return False


def classify_text(text_to_classify: str):
    """
    Classifies the given text using the loaded BERT model.

    Args:
        text_to_classify: The text string to classify.

    Returns:
        A dictionary containing the classification results:
        - "text": The original text.
        - "label": The predicted class ID (integer).
        - "score": The phishing probability score (float).
        If an error occurs, it returns:
        - "error": A description of the error.
        - "label": -1
        - "score": 0.0
        If the input text is empty, it returns:
        - "text": The input text.
        - "label": 0 (considered legitimate by default for empty text)
        - "score": 0.0
        - "info": "Empty text rated as legitimate"
    """
    # Check if the model and tokenizer have been loaded.
    if not MODEL_BERT or not TOKENIZER_BERT:
        print("BERT-Classifier: Model not loaded. Classification not possible.")
        return {"error": "Model not loaded", "label": -1, "score": 0.0}

    # Handle empty or whitespace-only input text.
    if not text_to_classify or not text_to_classify.strip():
        print("BERT-Classifier: Empty text received for classification.")
        # Default classification for empty text.
        return {"text": text_to_classify, "label": 0, "score": 0.0, "info": "Empty text rated as legitimate"}

    print(f"BERT-Classifier: Classifying text (first 100 characters): '{text_to_classify[:100]}...'")
    try:
        # Tokenize the input text.
        # - return_tensors="pt": Returns PyTorch tensors.
        # - truncation=True: Truncates sequences longer than max_length.
        # - max_length=512: Maximum sequence length for BERT models.
        # - padding=True: Pads shorter sequences to the length of the longest sequence in the batch.
        inputs = TOKENIZER_BERT(
            text_to_classify,
            return_tensors="pt",
            truncation=True,
            max_length=512,
            padding=True
        ).to(DEVICE_BERT)  # Move tokenized inputs to the same device as the model.

        # Perform inference without calculating gradients (saves memory and computation).
        with torch.no_grad():
            outputs = MODEL_BERT(**inputs)

        # Get the raw output scores (logits) from the model.
        logits = outputs.logits
        # Convert logits to probabilities using the softmax function.
        # Softmax is applied along the last dimension (-1), which corresponds to the class scores.
        probabilities = torch.softmax(logits, dim=-1)

        # Assuming the model is binary (or multi-class where index 1 is the "phishing" class).
        # Get the probability score for the "phishing" class (index 1).
        phishing_score = probabilities[0][1].item()  # .item() converts a single-element tensor to a Python number.
        # Get the predicted class ID by finding the index of the highest probability.
        predicted_class_id = torch.argmax(probabilities, dim=-1).item()

        print(
            f"BERT-Classifier: Text classified as Label {predicted_class_id} with Phishing-Score {phishing_score:.4f}")
        return {"text": text_to_classify, "label": predicted_class_id, "score": phishing_score}
    except Exception as e:
        print(f"BERT-Classifier: Error during classification: {e}")
        return {"error": str(e), "label": -1, "score": 0.0}
