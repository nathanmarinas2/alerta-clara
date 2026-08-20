FROM python:3.13-slim-trixie AS runtime

# La cadena de OCR (rapidocr -> opencv -> ffmpeg) no forma parte de esta imagen.
# Vive en el extra [ocr] y se despliega por separado, por tres razones:
#   - Peso: onnxruntime y opencv suman cientos de MB para una función que solo
#     interviene cuando alguien sube una captura.
#   - CPU: el reconocimiento de texto bloquea el proceso que atiende peticiones.
#   - CVE irresolubles desde aquí: opencv enlaza libavcodec por DT_NEEDED en Linux
#     y rapidocr-onnxruntime declara Requires-Python <3.13, lo que impedía subir
#     de versión de CPython.
# La aplicación degrada de forma explícita si el OCR no está instalado.

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /srv/app

RUN groupadd --system alerta && useradd --system --gid alerta --home-dir /srv/app alerta

COPY requirements-runtime.lock pyproject.toml README.md ./
COPY alembic.ini ./
COPY migrations ./migrations
COPY models ./models
COPY app ./app

RUN apt-get update \
    && apt-get upgrade -y \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-deps -r requirements-runtime.lock \
    && python -m pip install --no-deps . \
    && python -c "import app.main; from app.services.ocr import extract_text_from_image; \
assert extract_text_from_image(b'no-es-una-imagen') == '', 'el OCR debe degradar en silencio'; \
print('API operativa; OCR ausente y degradando correctamente')" \
    && python -m pip uninstall --yes pip setuptools

USER alerta
EXPOSE 8000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips \"${FORWARDED_ALLOW_IPS:-127.0.0.1}\""]
