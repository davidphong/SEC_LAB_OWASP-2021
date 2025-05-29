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

# Set permissions for the start script
RUN chmod +x ./start.sh

# Initialize database
RUN python -c "from app import init_db; init_db()"

# Expose ports for main app and internal service
EXPOSE 5001
EXPOSE 745

# Run the application using the start script
CMD ["/bin/bash","./start.sh"]
