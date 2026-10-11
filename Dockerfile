FROM python:3.11-slim

WORKDIR /app

# Copy dependency requirements
COPY requirements.txt /app/requirements.txt

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy FastAPI backend and frontend source code
COPY main.py /app/main.py
COPY index.html /app/index.html
COPY static /app/static

# Hugging Face Spaces port defaults to 7860
EXPOSE 7860

# Run uvicorn on port 7860
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "7860"]
