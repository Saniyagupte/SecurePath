FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# System deps: git for cloning repos, nodejs/npm for semgrep JS rules
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# gunicorn for production WSGI serving
RUN pip install --no-cache-dir gunicorn==22.0.0

COPY . .

# ---------------------------------------------------------------------------
# Runtime environment variables
# Set real values in Railway / Render dashboard — never hardcode secrets here
# ---------------------------------------------------------------------------
ENV GROQ_API_KEY=""
ENV EXAI_PROVIDER=groq
ENV EXAI_MODEL=llama-3.3-70b-versatile
ENV FLASK_ENV=production

# DATA_DIR points to the persistent volume mount.
# On Railway: create a volume and mount it at /data
# On Render:  create a Disk and mount it at /data
# Locally:    leave unset — SQLite & reports go in the project folder
ENV DATA_DIR=/data

# PORT is injected automatically by Railway and Render
EXPOSE 8000

# Use gunicorn with 2 workers (keep low for free tier RAM limits).
# init_db() is called inside app.py __main__, so we call it via a startup script.
CMD ["sh", "-c", "python -c 'from db import init_db; init_db()' && gunicorn --bind 0.0.0.0:${PORT:-8000} --workers 2 --timeout 300 --access-logfile - app:app"]
