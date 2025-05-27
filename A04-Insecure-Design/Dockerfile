# Image gọn ~110 MB
FROM python:3.10-alpine
WORKDIR /app

# Copy application code
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create flag file
RUN echo "VNPT{INSECURE_DESIGN_TRUSTING_CLIENT_DATA_IS_DANGEROUS}" > flag.txt

# Create directory for static files if not exists
RUN mkdir -p static/desgined

# Expose port
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]
