import os

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel

# --- Environment Variable Loading ---
# Determine the project root directory to reliably find the .env file.
# __file__ is the path to the current script (main.py).
# os.path.dirname(__file__) gives the directory of main.py (bert_module).
# os.path.join(..., '..') goes one level up to the project root.
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
# Construct the full path to the .env file located in the project root.
dotenv_path = os.path.join(project_root, '.env')

# Load environment variables from the .env file.
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path=dotenv_path)
else:
    # If .env is not found at the constructed path, print a message and attempt to load
    # from default locations (e.g., current working directory).
    print(f"BERT-Service: .env file not found at {dotenv_path}, attempting default load.")
    load_dotenv()

# Import model loading and classification functions from the bert_classifier module.
# This import is placed after dotenv loading to ensure environment variables are available.
from bert_classifier import load_model, classify_text

# --- FastAPI Application Initialization ---
# Create an instance of the FastAPI application.
app = FastAPI()


# --- Pydantic Model for Request Body ---
class ClassificationRequest(BaseModel):
    """
    Defines the expected structure for the request body of the /classify_text/ endpoint.
    It expects a JSON object with a single key "text" of type string.
    """
    text: str


# --- Application Startup Event ---
@app.on_event("startup")
async def startup_event():
    """
    This function is executed when the FastAPI application starts up.
    Its primary purpose here is to load the BERT model so it's ready for requests.
    """
    print("BERT-Service: FastAPI application starting...")
    if not load_model():
        # If model loading fails, print an error. The application will still start,
        # but classification requests will likely fail or be handled by error checks.
        print("BERT-Service: ERROR - Model could not be loaded at startup. Check logs.")
    else:
        print("BERT-Service: Model successfully initialized.")


# --- Classification Endpoint ---
@app.post("/classify_text/")
async def classify_text_endpoint(request: ClassificationRequest = Body(...)):
    """
    Endpoint to classify a given text for phishing detection.
    It expects a POST request with a JSON body containing the text to be classified.
    """
    print(f"BERT-Service: Classification request received.")

    # Handle cases where the text is empty or contains only whitespace.
    # The bert_classifier.classify_text function has specific handling for empty strings.
    if not request.text or not request.text.strip():
        print("BERT-Service: Request with empty text received.")
        # Call classify_text even for empty text, as it might have specific logic.
        result = classify_text(request.text)
        # If the classifier explicitly returns an error for empty text.
        if "error" in result:
            raise HTTPException(status_code=400, detail=result["error"])
        return result

    # Call the classification function from the bert_classifier module.
    result = classify_text(request.text)

    # Handle potential errors returned by the classification function.
    if "error" in result:
        print(f"BERT-Service: Error from bert_classifier: {result['error']}")
        # Raise an HTTP 500 error if classification failed.
        raise HTTPException(status_code=500, detail=result["error"])

    # If classification is successful, return the result.
    print(
        f"BERT-Service: Classification result returned: Label {result['label']}, Score {result['score']:.4f}"
    )
    return result


# This print statement executes when the Python script is first parsed.
# It indicates that the FastAPI application routes and events have been defined.
print("BERT-Service: FastAPI application defined.")
