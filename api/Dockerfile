FROM python:3.11-slim
ENV PYTHONUNBUFFERED=1
WORKDIR /app
RUN apt-get update && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
COPY main.py /app/
COPY token_verify.py /app/
EXPOSE 3001
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "3001"]
