# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Install system dependencies for building Python packages (netifaces)
RUN apt-get update && apt-get install -y \
    build-essential \
    python3-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app

# Copy project files into the container
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Expose the port (Flask app listens on PORT)
EXPOSE 8080

# Default environment variables (can be overridden at runtime)
ENV STORAGE_DIR=/app/storage
ENV PORT=8080

CMD ["python", "app.py"]
