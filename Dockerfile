FROM python:3.12-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv/app

RUN groupadd --system alerta && useradd --system --gid alerta --home-dir /srv/app alerta

COPY requirements-runtime.lock pyproject.toml README.md ./
COPY models ./models
COPY app ./app
RUN python -m pip install --no-deps -r requirements-runtime.lock && python -m pip install --no-deps .

USER alerta
EXPOSE 8000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips \"${FORWARDED_ALLOW_IPS:-127.0.0.1}\""]
