FROM python:3.8-slim

WORKDIR /app

# Running as root — insecure container configuration
USER root

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY src/ ./src/

# Hardcoded credentials in environment variables
ENV AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
ENV AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
ENV DB_PASSWORD=password123
ENV SECRET_KEY=hardcoded_flask_secret_key_abc123

EXPOSE 5000
CMD ["python", "src/app.py"]
