import os
import shutil

from fastapi import FastAPI, UploadFile, File, HTTPException

from ocr_processor import perform_ocr_on_file

# --- FastAPI Application Setup ---
app = FastAPI()

# --- Temporary File Upload Directory ---
# Defines the directory where uploaded files will be temporarily stored for processing.
TEMP_UPLOAD_DIR = "/app/temp_uploads_ocr"
# Creates the temporary upload directory if it doesn't already exist.
# `exist_ok=True` prevents an error if the directory already exists.
os.makedirs(TEMP_UPLOAD_DIR, exist_ok=True)

print("OCR-Service: FastAPI application started.")


# --- OCR Endpoint ---
@app.post("/extract_text_from_file/")
async def ocr_endpoint(file: UploadFile = File(...)):
    """
    FastAPI endpoint to extract text from an uploaded file (image or PDF).
    The file is temporarily saved, processed by OCR, and then the temporary file is deleted.

    Args:
        file: An UploadFile object representing the uploaded file.
              FastAPI handles the file upload mechanism.

    Returns:
        A JSON response containing the filename and the extracted OCR text.
        Raises HTTPException on processing errors.
    """
    # Construct the full path for storing the temporary file.
    temp_file_path = os.path.join(TEMP_UPLOAD_DIR, file.filename)
    print(f"OCR-Service: Receiving file: {file.filename} for OCR.")

    try:
        # Save the uploaded file to the temporary directory.
        # "wb" opens the file in binary write mode.
        # shutil.copyfileobj efficiently copies the file-like object's content.
        with open(temp_file_path, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)
        print(f"OCR-Service: File '{file.filename}' temporarily saved at {temp_file_path}")

        # Perform OCR processing on the saved temporary file.
        extracted_text = perform_ocr_on_file(temp_file_path)

        # Simple error check based on ocr_processor output.
        # The ocr_processor module returns specific German error strings upon failure.
        if "OCR-Fehler" in extracted_text:  # Check for German error prefix from ocr_processor
            print(f"OCR-Service: Error during OCR processing for '{file.filename}'. Detail: {extracted_text}")
            # If an OCR error is detected, raise an HTTPException (500 Internal Server Error).
            # The detail of the exception is the error message from ocr_processor.
            raise HTTPException(status_code=500, detail=extracted_text)

        # If OCR is successful, log completion and return the results.
        print(f"OCR-Service: Text extraction for '{file.filename}' completed.")
        return {"filename": file.filename, "ocr_text": extracted_text}

    except HTTPException as http_exc:
        # If an HTTPException was raised (e.g., by the OCR error check above),
        # re-raise it to be handled by FastAPI's default exception handling.
        raise http_exc
    except Exception as e:
        # Catch any other unexpected exceptions during the endpoint processing.
        print(f"OCR-Service: Unexpected error in endpoint for '{file.filename}': {e}")
        # Raise a generic 500 Internal Server Error for other types of failures.
        raise HTTPException(status_code=500, detail=f"General server error during OCR: {str(e)}")
    finally:
        # This block ensures that the temporary file is deleted,
        # whether the processing was successful or an error occurred.
        if os.path.exists(temp_file_path):
            os.remove(temp_file_path)
            print(f"OCR-Service: Temporary file '{temp_file_path}' deleted.")
