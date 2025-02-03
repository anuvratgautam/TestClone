# pdfapp/forms.py

from django import forms
from .models import PDF
from django.contrib.auth.models import User

class PDFForm(forms.ModelForm):
    class Meta:
        model = PDF
        fields = ['title', 'pdf_file']
        widgets = {
            'title': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'Enter PDF title'}),
            'pdf_file': forms.FileInput(attrs={'class': 'form-control'}),
        }


# forms.py
class RegisterForm(forms.ModelForm):
    password = forms.CharField(widget=forms.PasswordInput)
    password_confirm = forms.CharField(widget=forms.PasswordInput, label='Confirm Password')
    email = forms.EmailField(required=True)

    class Meta:
        model = User
        fields = ['username', 'email', 'password', 'password_confirm']

    def clean(self):
        cleaned_data = super().clean()
        password = cleaned_data.get('password')
        password_confirm = cleaned_data.get('password_confirm')
        email = cleaned_data.get('email')
        
        if password and password_confirm and password != password_confirm:
            raise forms.ValidationError("Passwords do not match")
            
        # Check if email already exists
        if email and User.objects.filter(email=email).exists():
            raise forms.ValidationError("Email already registered")
        
        return cleaned_data