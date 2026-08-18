# Seguridad

No pegues mensajes reales con contraseñas, códigos de un solo uso o datos bancarios en
incidencias públicas. La aplicación redacta identificadores conocidos, pero ningún detector de
información personal es perfecto.

Para comunicar una vulnerabilidad, abre un aviso privado al responsable del repositorio e incluye
la versión, el endpoint afectado y una reproducción mínima sin datos personales.

Antes de desplegar:

- configura `SERVER_PEPPER`, `REVIEW_TOKENS` y `BROWSER_SCANNER_TOKEN` con secretos distintos;
- ejecuta `alembic upgrade head` sobre una copia de la base de datos;
- activa los análisis de dependencias y de la imagen del workflow;
- mantén `ALLOW_EXTERNAL_IMAGE_ANALYSIS=false` salvo consentimiento explícito;
- publica `/metrics` únicamente detrás de una red o autenticación de operaciones.
