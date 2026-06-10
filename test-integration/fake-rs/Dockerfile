FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py protected_resource.txt ./
EXPOSE 8000
# 1 worker keeps the lazily-built JWKS cache simple for a demo.
CMD ["gunicorn", "-b", "0.0.0.0:8000", "-w", "1", "app:app"]
