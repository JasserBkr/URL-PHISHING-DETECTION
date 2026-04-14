FROM python:3.11-slim

#Install system deps needed by your libraries
RUN apt-get update && apt-get install -y \
    gcc \
    libgomp1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

#Copy and install Python dependencies
COPY backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

#Copy backend code
COPY backend/ ./backend/

#Copy frontend
COPY web_app/ ./web_app/

EXPOSE 8000

CMD ["python", "backend/main.py"]