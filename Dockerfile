FROM python:3.14-slim
WORKDIR /app

# Install build deps and runtime deps declared in pyproject
COPY certify-serve/pyproject.toml /app/
COPY certify-serve/src/ /app/src/

# Install runtime dependencies by installing the package in this image.
# This ensures `certify_server` is available on PYTHONPATH even when the
# project directory is mounted at runtime by docker-compose.
RUN pip install --upgrade pip setuptools wheel \
    && pip install --no-cache-dir . pytest

EXPOSE 8000
CMD ["python", "-m", "uvicorn", "certify_server.main:app", "--host", "0.0.0.0", "--port", "8000"]
