# Image gọn ~110 MB
FROM python:3.9-slim

# Set working directory
WORKDIR /app

# Install required packages
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create non-root user
RUN adduser --disabled-password --gecos "" appuser

# Create a separate user for the flag file with minimal permissions
RUN adduser --disabled-password --gecos "" flaguser

# Set permissions
RUN chown -R appuser:appuser /app && \
    chmod -R 0555 /app && \
    chmod -R 0444 /app/*.py && \
    chmod -R 0444 /app/templates && \
    chmod -R 0444 /app/static && \
    chown flaguser:flaguser flag.txt && \
    chmod 0444 flag.txt && \
    mkdir -p /app/instance && \
    chown appuser:appuser /app/instance && \
    chmod 0755 /app/instance

# Create database directory with write permissions for the app
RUN mkdir -p /app/data && \
    chown appuser:appuser /app/data && \
    chmod 0755 /app/data

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
ENV SQLALCHEMY_DATABASE_URI='sqlite:///data/data.db'

# Initialize database
USER appuser
RUN python -c "from app import app, init_db; init_db()"

# Expose port
EXPOSE 5001

# Run the application
CMD ["python", "run.py"]
