from django.db import models
from django.contrib.auth.models import User

class PDF(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE, default=1) 
    title = models.CharField(max_length=200)
    pdf_file = models.FileField(upload_to='pdfs/')
    uploaded_at = models.DateTimeField(auto_now_add=True)
    analysis = models.TextField(null=True, blank=True)
    analyzed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return self.title
    

class Document(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    file = models.FileField(upload_to='documents/')
    analysis = models.TextField(null=True, blank=True)
    uploaded_at = models.DateTimeField(auto_now_add=True)
    analyzed_at = models.DateTimeField(null=True, blank=True)

    def __str__(self):
        return f"{self.name} - {self.user.username}"

    class Meta:
        ordering = ['-uploaded_at']
