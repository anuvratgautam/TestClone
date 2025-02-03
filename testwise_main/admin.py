from django.contrib import admin
from .models import PDF

@admin.register(PDF)
class PDFAdmin(admin.ModelAdmin):
    list_display = ('title', 'uploaded_at')
    search_fields = ('title',)
