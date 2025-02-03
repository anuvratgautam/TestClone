from django.shortcuts import render, redirect, get_object_or_404
from django.views.decorators.http import require_POST
import PyPDF2
from .ai_handlers import generate_questions_with_mistral
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.decorators import login_required
from django.contrib.auth.mixins import LoginRequiredMixin
from django.views import View
from django.contrib.auth.models import User
from django.contrib import messages
from django.core.mail import send_mail
from django.conf import settings
import random
from .models import PDF,Document
from .forms import PDFForm, RegisterForm
from mistralai import Mistral
from PIL import Image
import pytesseract
from testwise_main.models import PDF
from .ai_handlers import DocumentAnalyzer
from django.utils import timezone
import logging
import json
from django.http import JsonResponse

def generate_otp():
    return random.randint(100000, 999999)

def send_otp_email(email, otp):
    subject = 'Verify Your Email - OTP'
    message = f'Your OTP for email verification is: {otp}'
    from_email = settings.EMAIL_HOST_USER
    recipient_list = [email]
    
    try:
        send_mail(subject, message, from_email, recipient_list)
        return True
    except Exception as e:
        print(f"Error sending email: {e}")
        return False

def register_view(request):
    if request.method == "POST":
        form = RegisterForm(request.POST)
        if form.is_valid():
            username = form.cleaned_data.get("username")
            password = form.cleaned_data.get("password")
            email = form.cleaned_data.get("email")
            
            
            if User.objects.filter(email=email).exists():
                messages.error(request, 'Email already registered.')
                return render(request, 'testwise_main/register.html', {'form': form})
            
           
            try:
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    password=password,
                    is_active=False
                )
                print(f"DEBUG: User created - {username}")
            except Exception as e:
                print(f"DEBUG: User creation error - {e}")
                messages.error(request, 'Error creating user. Please try again.')
                return render(request, 'testwise_main/register.html', {'form': form})
            
           
            otp = generate_otp()
            request.session['signup_otp'] = otp
            request.session['user_email'] = email
            
            
            request.session.modified = True
            
            print(f"DEBUG: OTP generated - {otp}")
            print(f"DEBUG: Session OTP - {request.session.get('signup_otp')}")
            print(f"DEBUG: Session Email - {request.session.get('user_email')}")
            
            if send_otp_email(email, otp):
                messages.success(request, 'Please check your email for OTP verification.')
                return redirect('verify_email')
            else:
                
                user.delete()
                messages.error(request, 'Failed to send verification email. Please try again.')
    else:
        form = RegisterForm()
    return render(request, 'testwise_main/register.html', {'form': form})

def verify_email(request):
    print("DEBUG: Entering verify_email view")
    
    
    user_email = request.session.get('user_email')
    stored_otp = request.session.get('signup_otp')
    
    print(f"DEBUG: User email in session - {user_email}")
    print(f"DEBUG: Stored OTP in session - {stored_otp}")
    
    if not user_email:
        print("DEBUG: No email in session, redirecting to register")
        messages.error(request, 'Session expired. Please register again.')
        return redirect('register')
    
    if request.method == 'POST':
        user_otp = request.POST.get('otp')
        print(f"DEBUG: User submitted OTP - {user_otp}")
        
        if stored_otp and str(stored_otp) == str(user_otp):
            try:
                user = User.objects.get(email=user_email)
                user.is_active = True
                user.save()
                
                
                del request.session['signup_otp']
                del request.session['user_email']
                request.session.modified = True
                
                messages.success(request, "Email verified successfully! Please login.")
                return redirect('login')
            except User.DoesNotExist:
                messages.error(request, "User not found. Please register again.")
                return redirect('register')
        else:
            messages.error(request, "Invalid OTP. Please try again.")
            return render(request, 'testwise_main/verify.html', {'email': user_email})
    
    print("DEBUG: Rendering verify.html")
    return render(request, 'testwise_main/verify.html', {'email': user_email})

def login_view(request):
    error_message = None 
    if request.method == "POST":  
        username = request.POST.get("username")  
        password = request.POST.get("password")  
        user = authenticate(request, username=username, password=password)  
        if user is not None:
            if user.is_active:  
                login(request, user)  
                next_url = request.POST.get('next') or request.GET.get('next') or 'pdf_list'
                return redirect(next_url) 
            else:
                error_message = "Please verify your email first."
        else:
            error_message = "Invalid credentials"  
    return render(request, 'testwise_main/login.html', {'error': error_message})

def logout_view(request):
    if request.method == "POST":
        logout(request)
        return redirect('login')
    else:
        return redirect('pdf_list')

@login_required(login_url='login')
def pdf_list(request):
    pdfs = PDF.objects.filter(user=request.user).order_by('-uploaded_at')
    form = PDFForm()
    return render(request, 'testwise_main/pdf_list.html', {'pdfs': pdfs, 'form': form})

@login_required(login_url='login')
def upload_pdf(request):
    if request.method == 'POST':
        form = PDFForm(request.POST, request.FILES)
        if form.is_valid():
            pdf = form.save(commit=False)
            pdf.user = request.user  
            pdf.save()
            messages.success(request, 'PDF uploaded successfully.')
        else:
            messages.error(request, 'Failed to upload PDF. Please ensure the file is a PDF.')
    return redirect('pdf_list')

@login_required(login_url='login')
def delete_pdf(request, pk):
    pdf = get_object_or_404(PDF, pk=pk, user=request.user)
    if request.method == 'POST':
        pdf.pdf_file.delete()
        pdf.delete()
        messages.success(request, 'PDF deleted successfully.')
    return redirect('pdf_list')

def extract_text_from_image(image_file_path):
    """Extract text from an image using Tesseract OCR."""
    image = Image.open(image_file_path)
    text = pytesseract.image_to_string(image)
    return text

def get_mistral_response(prompt):
    """Generate a response using Mistral API."""
    try:
        api_key = settings.MISTRAL_API_KEY  
        client = Mistral(api_key=api_key)

        response = client.chat.complete(
            model="mistral-large-latest",
            messages=[
                {
                    "role": "user",
                    "content": prompt,
                },
            ],
        )
        return response.choices[0].message.content
    except Exception as e:
        return f"Error generating response: {e}"


logger = logging.getLogger(__name__)


@login_required(login_url='login')
def llm(request):
    try:
        logger.info("Starting LLM view function")
        user_pdfs = PDF.objects.filter(user=request.user).order_by('-uploaded_at')
        
       
        unanalyzed_pdfs = user_pdfs.filter(analysis__isnull=True)
        if unanalyzed_pdfs.exists():
            analyzer = DocumentAnalyzer()
            logger.info(f"Found {unanalyzed_pdfs.count()} PDFs to analyze")
            
            for pdf in unanalyzed_pdfs:
                try:
                    logger.info(f"Analyzing PDF: {pdf.title}")
                    
                    file_path = pdf.pdf_file.path
                    
                    
                    analysis = analyzer.analyze_document(file_path)
                    
                    
                    pdf.analysis = analysis
                    pdf.analyzed_at = timezone.now()
                    pdf.save()
                    logger.info(f"Successfully analyzed PDF: {pdf.title}")
                    
                except Exception as e:
                    logger.error(f"Error analyzing PDF {pdf.title}: {str(e)}")
                    messages.error(request, f"Error analyzing {pdf.title}: {str(e)}")
                    continue
        
        return render(request, 'testwise_main/llm_page.html', {'user_pdfs': user_pdfs})
        
    except Exception as e:
        logger.error(f"General error in LLM view: {str(e)}")
        messages.error(request, f"Error processing PDFs: {str(e)}")
        return redirect('pdf_list')
    
@require_POST
@login_required(login_url='login')
def generate_questions_view(request, pdf_id):
    try:
        pdf = get_object_or_404(PDF, id=pdf_id, user=request.user)
        text_content = extract_pdf_text(pdf.pdf_file)
        data = json.loads(request.body)
        num_questions = data.get('num_questions', 5)
        
        generated_content = generate_questions_with_mistral(
            text_content=text_content,
            num_questions=num_questions
        )
        
        # Store with PDF-specific key
        request.session[f'generated_{pdf_id}'] = generated_content
        request.session.modified = True
        return JsonResponse({'generated_content': generated_content})
        
    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)

@login_required(login_url='login')
def download_summary(request, pdf_id):
    generated_content = request.session.get(f'generated_{pdf_id}', 'No content generated yet')
    response = HttpResponse(generated_content, content_type='text/plain')
    response['Content-Disposition'] = f'attachment; filename="questions_{pdf_id}.txt"'
    return response

def extract_pdf_text(file):
    text = ""
    try:
        with file.open('rb') as f:
            reader = PyPDF2.PdfReader(f)
            for page in reader.pages:
                text += page.extract_text() + "\n"
    except PyPDF2.errors.PdfReadError:
        raise ValueError("Invalid PDF file format")
    except Exception as e:
        raise RuntimeError(f"Error reading PDF: {str(e)}")
    return text