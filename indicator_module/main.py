import os
from typing import Optional, Dict, Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel, Field

# --- Environment Variable Loading ---
# Construct the absolute path to the project root directory.
# This assumes 'main.py' is in 'indicator_module', which is a subdirectory of the project root.
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
# Define the expected path for the .env file in the project root.
dotenv_path = os.path.join(project_root, '.env')

# Load environment variables from the .env file if it exists.
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path=dotenv_path)
else:
    # If .env is not found at the specific path, try loading from default locations
    # (e.g., current working directory), or rely on system-set environment variables.
    print(f"Indicator-Service: .env file not found at {dotenv_path}, attempting default load.")
    load_dotenv()

# Import functions from the indicator_extractor module.
# This is done after loading .env to ensure that the extractor module
# has access to necessary environment variables upon its own import/initialization.
from indicator_extractor import initialize_llamacpp_client_config, extract_indicators_from_llamacpp_server

# --- FastAPI Application Initialization ---
# Create an instance of the FastAPI application.
# This 'app' object will be used to define API routes and event handlers.
app = FastAPI()


# --- Pydantic Model for Request Body ---
class IndicatorRequest(BaseModel):
    """
    Defines the expected structure and data types for the request body
    of the /extract_indicators/ endpoint.
    Pydantic performs automatic validation of incoming request data against this model.
    """
    text: str  # The email text content to be analyzed for indicators.
    # Optional field for analysis context, defaults to an empty dictionary if not provided.
    # This can be used to pass additional metadata or context for the analysis if needed in the future.
    analysis_context: Optional[Dict[str, Any]] = Field(default_factory=dict)


# --- Application Startup Event Handler ---
@app.on_event("startup")
async def startup_event():
    """
    This function is registered to run when the FastAPI application starts up.
    It initializes the Llama.cpp client configuration.
    """
    print("Indicator-Service (Llama.cpp Client): FastAPI application starting...")
    # Attempt to initialize the configuration for the Llama.cpp server client.
    if not initialize_llamacpp_client_config():
        # If initialization fails, log an error. The application will still start,
        # but indicator extraction will likely fail, returning error responses.
        print(
            "Indicator-Service (Llama.cpp Client): ERROR - Llama.cpp Server config could not be initialized."
        )
    else:
        print("Indicator-Service (Llama.cpp Client): Llama.cpp Server config successfully initialized.")


# --- API Endpoint for Indicator Extraction ---
@app.post("/extract_indicators/")
async def extract_indicators_endpoint(request: IndicatorRequest = Body(...)):
    """
    FastAPI endpoint to extract phishing indicators from provided text.
    It expects a POST request with a JSON body conforming to the IndicatorRequest model.
    """
    print(f"Indicator-Service (Llama.cpp Client): Indicator extraction request received.")

    # Basic validation: Check if the input text is empty or contains only whitespace.
    if not request.text or not request.text.strip():
        # Return a specific error response for empty input.
        # The label "error_empty_text" can be used by clients to identify this specific error.
        return {"error": "Empty text provided", "label": "error_empty_text", "indicators": []}

    # Call the core function to extract indicators using the Llama.cpp server.
    # Pass the email text and any analysis context from the request.
    result = extract_indicators_from_llamacpp_server(request.text, request.analysis_context)

    # Check if the result from the extractor indicates an error.
    # Errors are typically identified by an "error" key in the result dictionary and a label starting with "error_".
    if "error" in result and result.get("label", "").startswith("error"):
        print(f"Indicator-Service (Llama.cpp Client): Error from indicator_extractor: {result['error']}")
        # If an error occurred in the extractor, raise an HTTPException.
        # This will send a 500 Internal Server Error response to the client.
        # The 'detail' of the HTTP exception is taken from the 'error' message in the result.
        raise HTTPException(status_code=500, detail=result["error"])

    # If no error, log the successful extraction result and return it to the client.
    # The result dictionary typically contains 'label' and 'indicators'.
    print(
        f"Indicator-Service (Llama.cpp Client): Indicator extraction result: "
        f"Label '{result.get('label')}', Indicators: {result.get('indicators')}"
    )
    return result


# This print statement executes when the Python script is first parsed.
# It signifies that the FastAPI application, including its routes and event handlers,
# has been defined and is ready to be served by an ASGI server like Uvicorn.
print("Indicator-Service (Llama.cpp Client): FastAPI application defined.")
