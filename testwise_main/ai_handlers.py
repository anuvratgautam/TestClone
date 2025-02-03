import os
from mistralai import Mistral
import pytesseract
from PIL import Image
import fitz 
from django.conf import settings
import logging

logger = logging.getLogger(__name__)

# Existing DocumentAnalyzer class remains unchanged
class DocumentAnalyzer:
    def __init__(self):
        self.api_key = settings.MISTRAL_API_KEY
        print("Initializing DocumentAnalyzer with API key")
        self.model = "mistral-tiny"  
        self.client = Mistral(api_key=self.api_key)

    def extract_text_from_pdf(self, pdf_path):
        try:
            print(f"Attempting to extract text from PDF: {pdf_path}")
            
            doc = fitz.open(pdf_path)
            text = ""
            for page in doc:
                text += page.get_text()
            doc.close()
            
            if not text.strip():
                print("No text found in PDF, attempting OCR...")
                doc = fitz.open(pdf_path)
                for page_num in range(len(doc)):
                    page = doc[page_num]
                    pix = page.get_pixmap()
                    img = Image.frombytes("RGB", [pix.width, pix.height], pix.samples)
                    text += pytesseract.image_to_string(img) + "\n"
                doc.close()
            
            print(f"Successfully extracted text: {text[:200]}...")
            return text.strip()
        except Exception as e:
            print(f"Error in PDF extraction: {str(e)}")
            raise Exception(f"Error extracting text from PDF: {str(e)}")

    def analyze_with_mistral(self, text):
        try:
            print("Starting Mistral analysis...")
            
            prompt = f"""Please analyze this document and provide:
            1. A brief summary (2-3 sentences)
            2. Key points (up to 5)
            3. Main conclusions or recommendations

            Document text:
            {text[:4000]}  # Limiting text to avoid token limits
            """
            
            response = self.client.chat.complete(
                model=self.model,
                messages=[
                    {"role": "user", "content": prompt},
                ],
            )
            
            analysis = response.choices[0].message.content
            print(f"Received analysis from Mistral: {analysis[:200]}...")
            return analysis
            
        except Exception as e:
            print(f"Error in Mistral analysis: {str(e)}")
            raise Exception(f"Error in Mistral analysis: {str(e)}")

    def analyze_document(self, file_path):
        """Main method to analyze a PDF document"""
        try:
            print(f"Starting document analysis for: {file_path}")
            text = self.extract_text_from_pdf(file_path)
            
            if not text:
                raise Exception("No text could be extracted from the document")
                
            return self.analyze_with_mistral(text)
                
        except Exception as e:
            print(f"Error in document analysis: {str(e)}")
            raise Exception(f"Error analyzing document: {str(e)}")

# New question generation function added below
def generate_questions_with_mistral(text_content, num_questions=5):
    """Generate assessment questions using Mistral AI"""
    try:
        client = Mistral(api_key=settings.MISTRAL_API_KEY)
        
        prompt = f"""Generate {num_questions} exam questions based on this content:
        {text_content[:3000]}

        Requirements:
        - Mix of multiple choice and short answer
        - Include correct answers
        - Focus on key concepts
        - Use academic language
        - Format clearly with numbering"""
        
        response = client.chat.complete(
            model="mistral-large-latest",
            messages=[
                {"role": "user", "content": prompt},
            ],
            temperature=0.7,
            max_tokens=2000
        )
        
        return response.choices[0].message.content
        
    except Exception as e:
        logger.error(f"Mistral question generation failed: {str(e)}")
        raise Exception(f"Question generation error: {str(e)}")