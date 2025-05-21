# Image gọn ~110 MB
FROM python:3.9-slim
WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_ENV=development
ENV PYTHONUNBUFFERED=1

# Set a different port to avoid conflicts
ENV PORT=5001

# Initialize database
RUN python -c "from app import init_db; init_db()"

# Expose port
EXPOSE 5001

# Run the application
CMD ["python", "run.py"]
