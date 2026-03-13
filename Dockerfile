FROM python:3.12-slim
WORKDIR /app

# Install build deps and runtime deps declared in pyproject
COPY pyproject.toml /app/
COPY src/ /app/src/

RUN pip install --upgrade pip setuptools wheel \
    && pip install .[default] || true \
    && pip install fastapi uvicorn[standard] python-multipart certify-attendance

EXPOSE 8000
CMD ["uvicorn", "certify_server.main:app", "--host", "0.0.0.0", "--port", "8000"]
