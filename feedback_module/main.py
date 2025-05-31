import os
from typing import Dict, Any

from dotenv import load_dotenv
from fastapi import FastAPI, HTTPException, Body
from pydantic import BaseModel

# --- Environment Variable Loading ---
# Determine the project root directory to reliably find the .env file.
# __file__ is the path to the current script (main.py).
# os.path.dirname(__file__) gives the directory of main.py (feedback_module).
# os.path.join(..., '..') goes one level up to the project root.
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
# Construct the full path to the .env file located in the project root.
dotenv_path = os.path.join(project_root, '.env')

# Load environment variables from the .env file.
if os.path.exists(dotenv_path):
    load_dotenv(dotenv_path=dotenv_path)
else:
    # If .env is not found at the constructed path, print a message and attempt to load
    # from default locations (e.g., current working directory or system-wide).
    print(f"Feedback-Service: .env file not found at {dotenv_path}, attempting default load.")
    load_dotenv()

# Import functions from feedback_generator after .env loading to ensure
# SMTP environment variables are available to that module.
from feedback_generator import create_feedback_email_body, send_email

# --- FastAPI Application Initialization ---
# Create an instance of the FastAPI application. This will be used to define routes.
app = FastAPI()


# --- Pydantic Model for Request Body ---
class FeedbackRequest(BaseModel):
    """
    Defines the expected structure and data types for the request body
    of the /send_feedback/ endpoint.
    """
    recipient_email: str  # The email address to send the feedback to.
    analysis_results: Dict[str, Any]  # The analysis results dictionary from the main pipeline.


# --- Application Startup Event ---
@app.on_event("startup")
async def startup_event():
    """
    This function is executed when the FastAPI application starts up.
    It checks for the presence of essential SMTP configuration environment variables.
    """
    print("Feedback-Service: FastAPI application starting...")
    # Check if all required SMTP environment variables are set.
    required_smtp_vars = ['SMTP_SERVER', 'SMTP_USER', 'SMTP_PASSWORD']
    if not all(os.getenv(var) for var in required_smtp_vars):
        print("Feedback-Service: WARNING - SMTP configuration variables (SMTP_SERVER, SMTP_USER, SMTP_PASSWORD) "
              "not completely set in .env. Email sending will likely fail.")
    else:
        print("Feedback-Service: SMTP configuration seems to be present.")


# --- Feedback Sending Endpoint ---
@app.post("/send_feedback/")
async def send_feedback_endpoint(request: FeedbackRequest = Body(...)):
    """
    FastAPI endpoint to receive analysis results and send a feedback email.
    It expects a POST request with a JSON body matching the FeedbackRequest model.
    """
    print(f"Feedback-Service: Request to send feedback to {request.recipient_email} received.")

    # Generate the email subject and body using the analysis results.
    # The content of the email (subject, body) will be in German.
    subject, body = create_feedback_email_body(request.analysis_results)

    # Attempt to send the email.
    success = send_email(request.recipient_email, subject, body)

    if success:
        # If email sending was successful, return a 200 OK response.
        # The "status" and "recipient" keys in the response are in English,
        # but "Feedback gesendet" is German as it was in the original code.
        print(f"Feedback-Service: Feedback successfully sent to {request.recipient_email}-marker.")
        return {"status": "Feedback gesendet", "recipient": request.recipient_email}
    else:
        # If email sending failed, log the error and raise an HTTP 500 Internal Server Error.
        # The detail message "Fehler beim Senden der Feedback-E-Mail" is German.
        print(f"Feedback-Service: Error sending feedback to {request.recipient_email}.")
        raise HTTPException(status_code=500, detail="Fehler beim Senden der Feedback-E-Mail")


# This print statement executes when the Python script is first parsed by the interpreter.
# It indicates that the FastAPI application (including routes, models, and event handlers)
# has been defined and is ready to be run by a ASGI server like Uvicorn.
print("Feedback-Service: FastAPI application defined.")
