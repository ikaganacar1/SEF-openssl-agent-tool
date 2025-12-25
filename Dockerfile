FROM python:3.11-slim

# Install OpenSSL
RUN apt-get update && apt-get install -y \
    openssl \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ .

# Expose port
EXPOSE 8025

# Run the application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8025"]
