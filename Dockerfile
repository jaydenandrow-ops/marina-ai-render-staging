FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /app
COPY requirements-render.lock ./requirements-render.lock
RUN python -m pip install --no-cache-dir -r requirements-render.lock \
    && useradd --system --uid 10001 --create-home marina

COPY --chown=marina:marina . .
USER marina

# Entrypoint validates PostgreSQL, TLS, proxy and staging lock settings before
# importing the FastAPI app. Uvicorn uses Render's assigned PORT, one worker.
CMD ["python", "render_entrypoint.py"]
