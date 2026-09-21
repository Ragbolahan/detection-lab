# Small official Python image.
FROM python:3.12-slim

WORKDIR /srv

# Install dependencies first, in their own layer. If only the app code
# changes, Docker reuses this layer and rebuilds are fast.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app

# Run as a normal user, not root. If the app is ever compromised, the
# attacker does not get root inside the container.
RUN useradd --create-home appuser
USER appuser

ENV SESSION_FILE=/tmp/sessions.json
EXPOSE 8000

# --no-access-log keeps stdout clean: one stream, one format, only our
# JSON security events. Easier to parse in phase 2.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--no-access-log"]
