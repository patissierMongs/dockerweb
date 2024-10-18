FROM python:3.9-slim

WORKDIR /app

# Install LibreOffice in the Docker container
RUN apt-get update && apt-get install -y libreoffice

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

CMD ["python", "app.py"]

