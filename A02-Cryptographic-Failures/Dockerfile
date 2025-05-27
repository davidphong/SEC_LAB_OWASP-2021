# Image gọn ~110 MB
FROM python:3.9-slim
WORKDIR /app

# Copy application code
COPY . /app/

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=development
ENV PYTHONUNBUFFERED=1

# Set a different port to avoid conflicts
ENV PORT=5000

# Initialize database
# RUN python -c "from app import init_db; init_db()"

# Expose port
EXPOSE 5000

# Run the application
CMD ["python", "app.py"]
