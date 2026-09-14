FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
COPY api_client.yaml /app/api_client.yaml

RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8088

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8088",  "--reload"]