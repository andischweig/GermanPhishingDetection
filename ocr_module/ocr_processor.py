import os

import pytesseract
from PIL import Image
from pdf2image import convert_from_path  # For converting PDF pages to images
from pyzbar.pyzbar import decode as decode_qr  # For decoding QR codes

# List of file extensions that are allowed for OCR processing.
ALLOWED_OCR_EXTENSIONS = ['.pdf', '.png', '.jpg', '.jpeg', '.tiff', '.bmp', '.gif']


def process_single_image(image_obj: Image.Image) -> str:
    """
    Processes a single image object to extract text using Tesseract OCR and decode QR codes.

    Args:
        image_obj: A PIL Image object to process.

    Returns:
        A string containing all extracted text from OCR and QR codes.
        Returns an empty string if no text or QR data is found, or German error
        strings in case of specific OCR failures.
    """
    full_extracted_text = ""
    qr_data_found = []  # To store data from any QR codes found in the image.

    # --- QR Code Decoding Section ---
    print("OCR-Processor: Attempting QR code decoding...")
    try:
        # decode_qr can find multiple QR codes in a single image.
        decoded_qrs = decode_qr(image_obj)
        if decoded_qrs:
            for qr in decoded_qrs:
                try:
                    # Attempt to decode QR data as UTF-8 first.
                    qr_data = qr.data.decode('utf-8')
                    print(f"OCR-Processor: QR code found and decoded. Data: {qr_data}")
                    qr_data_found.append(qr_data)
                except UnicodeDecodeError:
                    # If UTF-8 fails, try decoding as latin-1 as a fallback.
                    # This can be helpful for QR codes encoded with less common character sets.
                    print(
                        f"OCR-Processor: QR code data could not be decoded as UTF-8, "
                        f"trying latin-1. Raw data: {qr.data}"
                    )
                    try:
                        qr_data = qr.data.decode('latin-1')
                        print(f"OCR-Processor: QR code decoded with latin-1. Data: {qr_data}")
                        qr_data_found.append(qr_data)
                    except UnicodeDecodeError:
                        # If latin-1 also fails, log the failure.
                        print(f"OCR-Processor: QR code data could not be decoded as latin-1 either.")
        else:
            print("OCR-Processor: No QR codes found in the current image.")
    except Exception as e_qr:
        # Catch any other exceptions during QR code decoding.
        print(f"OCR-Processor: Error during QR code decoding: {e_qr}")

    # --- Tesseract OCR Section ---
    ocr_text_found = ""
    print("OCR-Processor: Starting Tesseract OCR text recognition...")
    try:
        # pytesseract.image_to_string performs OCR on the image object.
        # lang='deu+eng' specifies that Tesseract should look for German and English text.
        # This is important for emails that might contain text in either language.
        text_from_ocr = pytesseract.image_to_string(image_obj, lang='deu+eng')
        if text_from_ocr and text_from_ocr.strip():
            ocr_text_found = text_from_ocr.strip()
            print(f"OCR-Processor: Tesseract OCR text extracted (Length: {len(ocr_text_found)}).")
        else:
            print("OCR-Processor: No text found by Tesseract OCR in the current image.")
    except pytesseract.TesseractNotFoundError:
        # This specific exception means Tesseract is not installed or not in PATH.
        print("OCR-Processor: TESSERACT NOT FOUND.")
        # Error message: "OCR error: Tesseract not found." - Kept in German for consistency with potential error parsing.
        ocr_text_found = "OCR-Fehler: Tesseract nicht gefunden."
    except Exception as e_ocr:
        # Catch any other exceptions during Tesseract OCR processing.
        print(f"OCR-Processor: Error during Tesseract OCR: {e_ocr}")
        # Error message prefix: "OCR error:" - Kept in German for consistency.
        ocr_text_found = f"OCR-Fehler: {str(e_ocr)}"

    # --- Combine Extracted Data ---
    # Collect all extracted text parts (OCR and QR) into a list.
    parts = []
    if ocr_text_found:
        parts.append(ocr_text_found)
    if qr_data_found:
        # Extend the list if multiple QR codes were found and decoded.
        parts.extend(qr_data_found)

    # Join all parts with a newline character and strip any leading/trailing whitespace.
    full_extracted_text = "\n".join(parts).strip()

    return full_extracted_text


def perform_ocr_on_file(filepath: str) -> str:
    """
    Performs OCR and QR code extraction on a given file (PDF or image).

    Args:
        filepath: The path to the file to be processed.

    Returns:
        A string containing all extracted text. Returns an empty string if the
        file type is not supported or no text is found. Returns a German error
        string in case of processing failures.
    """
    print(f"OCR-Processor: Starting combined OCR/QR processing for file: {filepath}")
    final_text_output_parts = []  # To store text from each page of a PDF.

    try:
        file_extension = os.path.splitext(filepath)[1].lower()
        # Check if the file extension is in the list of allowed types.
        if file_extension not in ALLOWED_OCR_EXTENSIONS:
            print(f"OCR-Processor: File type {file_extension} is not supported.")
            return ""  # Return empty string for unsupported file types.

        if file_extension == ".pdf":
            # For PDF files, convert each page to an image.
            # dpi=200 is used for a reasonable quality for OCR; higher DPI means better quality
            # but slower processing and more memory usage.
            images_from_pdf = convert_from_path(filepath, dpi=200)
            for i, image_page in enumerate(images_from_pdf):
                print(f"OCR-Processor: Processing page {i + 1} of PDF {filepath}")
                # Process each page (now an image object) individually.
                page_text = process_single_image(image_page)
                if page_text:
                    final_text_output_parts.append(page_text)
            # Join text from all PDF pages, separated by a "PDF Page Break" marker.
            # This marker helps distinguish content from different pages in the final output.
            final_text_output = "\n--- PDF Page Break ---\n".join(final_text_output_parts).strip()
        else:
            # For single image files (PNG, JPG, etc.), open the image directly.
            print(f"OCR-Processor: Processing image file {filepath}")
            image_file_obj = Image.open(filepath)
            final_text_output = process_single_image(image_file_obj)

        # Remove any leading or trailing whitespace from the final combined output.
        cleaned_output = final_text_output.strip()
        if not cleaned_output:
            print(f"OCR-Processor: No text or QR data extracted from {filepath}.")
        else:
            print(
                f"OCR-Processor: Combined extraction for {filepath} completed. "
                f"Total length: {len(cleaned_output)}"
            )
        return cleaned_output

    except Exception as e:
        # Catch any general exceptions during file processing.
        print(f"OCR-Processor: Serious error during processing of {filepath}: {e}")
        # Error message prefix: "OCR processing error:" - Kept in German for consistency.
        # This error message might be used by upstream services for error identification.
        return f"OCR-Verarbeitungsfehler: {str(e)}"
