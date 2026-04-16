FROM python:3.11-slim

# Install system deps
RUN apt-get update && apt-get install -y \
    gcc \
    libgomp1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy and install Python dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy backend code
COPY backend/ ./backend/

# Copy frontend
COPY web_app/ ./web_app/

EXPOSE 8000
WORKDIR /app/backend

# Use uvicorn directly — NOT python main.py
# 0.0.0.0 so the port is reachable from outside the container
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
