FROM python:3.12-slim
WORKDIR /app
# Standard library only -- nothing to pip install.
COPY app.py .
EXPOSE 8080
CMD ["python", "-u", "app.py"]
