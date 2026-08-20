FROM python:3.13-slim-trixie AS runtime

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
    && python -m pip install --no-deps .

# OpenCV empaqueta FFmpeg para leer vídeo. El OCR solo usa funciones de imagen
# (cvtColor, resize, getPerspectiveTransform...), así que ese backend nunca entra
# en juego y únicamente añade superficie de CVE. La variante headless elimina la
# interfaz gráfica, no estos binarios: hay que borrarlos explícitamente.
#
# El borrado va seguido de una comprobación real de las funciones que usa el OCR:
# si alguna dejara de resolverse, la construcción falla aquí en vez de publicar una
# imagen con el reconocimiento de texto roto.
RUN find / -xdev \( -name 'libopencv_videoio_ffmpeg*' \
        -o -name 'libavcodec*' -o -name 'libavformat*' -o -name 'libavutil*' \
        -o -name 'libavdevice*' -o -name 'libswscale*' -o -name 'libswresample*' \) \
        -delete \
    && python -c "import numpy, cv2; \
img = numpy.zeros((32, 32, 3), dtype=numpy.uint8); \
cv2.cvtColor(img, cv2.COLOR_BGR2GRAY); \
cv2.resize(img, (16, 16)); \
print('OpenCV operativo sin FFmpeg')" \
    && python -m pip uninstall --yes pip setuptools

USER alerta
EXPOSE 8000

CMD ["sh", "-c", "uvicorn app.main:app --host 0.0.0.0 --port 8000 --proxy-headers --forwarded-allow-ips \"${FORWARDED_ALLOW_IPS:-127.0.0.1}\""]
