FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt
COPY app_main.py ./
CMD ["uvicorn", "app_main:app", "--host", "0.0.0.0", "--port", "3002", "--workers 1"]
