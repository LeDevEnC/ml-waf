FROM python:3.12-slim
WORKDIR /app

COPY deploiement/waf/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY notebooks/preprocessing.py .
COPY deploiement/waf/app.py .

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--no-server-header", "--no-date-header"]
