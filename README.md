# Alerta Clara

MVP de un asistente antiestafas para España. Lee un mensaje o una captura, extrae hechos,
contrasta señales técnicas y devuelve una decisión conservadora con una acción clara.

La idea central del producto se mantiene deliberadamente estricta:

```text
extracción → señales deterministas → decisión → explicación
```

El modelo puede ayudar a leer y redactar, pero **no puede cambiar el veredicto**. Solo existen dos
salidas de riesgo: `ESTAFA` y `NO PUEDO CONFIRMARLO`. Además se muestra una clasificación
descriptiva independiente (`phishing`, `spam`, `transaccional`, `personal` o `desconocido`). La
aplicación nunca afirma que un mensaje sea seguro.

## Qué incluye este primer corte

- Web accesible para pegar texto, añadir remitente o subir una captura.
- API FastAPI para texto y formularios multimodales.
- Clasificación local separada del tipo de mensaje para distinguir spam de phishing sin alterar el
  veredicto conservador.
- Extracción local sin coste, lectura local de QR y OCR local para capturas; extracción estructurada
  opcional con OpenAI.
- Redacción previa de IBAN, DNI, tarjetas, teléfonos y correos.
- Reglas para acceso remoto, códigos SMS, acciones sensibles, urgencia, móvil bancario,
  dominios no oficiales, typosquatting/homógrafos y TLD de riesgo.
- Señales URL locales para IP como host, punycode, longitud, subdominios, profundidad,
  palabras de suplantación, entropía y combo-squatting.
- Comprobaciones concurrentes y tolerantes a fallos: RDAP, certificado TLS y redirecciones.
- Trazabilidad por señal (`hit`, `miss`, `error`, `timeout`, `not_applicable`, `suppressed`), proveedor,
  versión y latencia, más el rastro de reglas que produjo el veredicto.
- Protección básica frente a SSRF, máximo de dominios y timeout por señal.
- Reputación en tres estados: indicador malicioso vigente, infraestructura compartida y dominio
  oficial. Ninguno se traduce en «seguro».
- Feeds locales versionados con procedencia, checksum, TTL, consenso y degradación al caducar.
- Correlación de campañas por artefactos (dominio, ruta, redirección, teléfono/IBAN como HMAC) y
  similitud textual; una campaña no es concluyente hasta quedar confirmada.
- Retrobúsqueda de análisis dudosos cuando aparecen indicadores nuevos, siempre hacia una cola de
  revisión humana y sin reescribir automáticamente el veredicto.
- Navegador Playwright opcional en un contenedor desechable sin acceso a Postgres ni Redis.
- Persistencia de mensaje redactado, extracción, señales, versión de reglas/modelo y feedback.
- Purga periódica del cuerpo, seudónimo y datos de extracción al vencer la retención configurada.
- Golden set con campaña, fecha, origen, tipo, señuelo y splits por grupo/tiempo; importador de CSV
  públicos y métricas por segmento.
- Clasificador auxiliar local de phishing (TF-IDF de caracteres + regresión logística), entrenable
  con un corpus español anonimizado y auditado. Su señal nunca sustituye al veredicto determinista.
- SQLite para desarrollo; Postgres y Redis preparados en Docker Compose.
- Rate limiting por IP, cabeceras de seguridad, métricas agregadas sin contenido y token opcional
  entre la API y el navegador aislado.
- Migraciones reproducibles con Alembic y workflow de CI con pruebas, auditoría de dependencias,
  Semgrep y escaneo de la imagen.

Consulta [la arquitectura](docs/architecture.md) para las decisiones, límites y siguiente orden de
construcción.

## Arranque local

Requiere Python 3.11 o posterior.

```powershell
py -3 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -e ".[dev]"
Copy-Item .env.example .env
uvicorn app.main:app --reload
```

Abre <http://127.0.0.1:8000>. La interfaz y el análisis de texto funcionan sin claves externas.

Los QR y el texto de una captura se procesan localmente y funcionan sin ninguna clave. Para enviar
una captura a un proveedor de visión debes configurar `OPENAI_API_KEY` y activar explícitamente
`ALLOW_EXTERNAL_IMAGE_ANALYSIS=true`; por defecto las imágenes no salen del servidor. El modelo
por defecto está fijado a un snapshot reproducible y puede cambiarse con `OPENAI_MODEL`.

### Entrenar el clasificador auxiliar

Descarga el corpus público anonimizado y entrena el modelo local:

```powershell
New-Item -ItemType Directory -Force data\external | Out-Null
Invoke-WebRequest `
  -Uri "https://data.mendeley.com/public-files/datasets/hz2d6gz7pc/files/f796c8e2-3768-4c2d-8b73-48f0d7771de5/file_downloaded" `
  -OutFile "data\external\spaphish_v5.csv"
.\.venv\Scripts\python.exe -m app.ml_training
```

El entrenamiento combina SpaPhish con un pequeño corpus de SMS en español para adaptar el modelo
a mensajes cortos. El resultado se guarda en `models/phishing_tfidf.joblib` y las métricas en
`models/phishing_tfidf.metrics.json`. El modelo solo aporta una señal de apoyo (15 puntos como
máximo cuando supera el umbral de confianza); las reglas duras y la abstención conservadora siguen
teniendo prioridad.

## Pruebas

```powershell
.\.venv\Scripts\python.exe -m pytest
.\.venv\Scripts\python.exe -m ruff check app tests
.\.venv\Scripts\python.exe -m app.evaluation
```

El golden set inicial sigue siendo sintético, aunque ya ejercita el corte temporal y por campaña. No
sustituye los 200 mensajes reales revisados que se necesitan antes del piloto. El importador elimina
identificadores y evita que una campaña cruce los splits. Consulta
[`eval/README.md`](eval/README.md) para ampliarlo.

## Inteligencia, retrobúsqueda y revisión

Los feeds están desactivados por defecto. Las políticas incluyen URLhaus y OpenPhish; se conservan
los snapshots antiguos para auditoría, pero no se vuelve a consultar el feed retirado de CERT.pl.
Para sincronizarlos manualmente y ejecutar después una retrobúsqueda:

```powershell
$env:ENABLE_THREAT_FEEDS = "true"
.\.venv\Scripts\python.exe -m app.threat_feeds sync
.\.venv\Scripts\python.exe -m app.retro_hunt
```

Las políticas auditables viven en `app/data/provider_policies.json`. Una fuente caducada no puntúa.
Los desacuerdos del usuario y los hallazgos retrospectivos entran en `/api/v1/reviews`. En
desarrollo se mantiene `X-Review-Key` por compatibilidad; para producción usa `REVIEW_TOKENS` con
formato `analista=secreto,admin=secreto`. También acepta `Authorization: Bearer ...`, exige el rol
`admin` para confirmar campañas y registra cada consulta/resolución en `audit_events`.

Tras actualizar una instalación existente ejecuta:

```powershell
.\.venv\Scripts\python.exe -m alembic upgrade head
```

## Docker

```powershell
Copy-Item .env.example .env
docker compose up --build
```

El servicio queda en `http://localhost:8000`. Para publicar con Caddy, configura `DOMAIN` y habilita
el perfil `edge`:

```powershell
$env:DOMAIN = "alerta.example.org"
docker compose --profile edge up --build -d
```

Antes de producción cambia `APP_ENV=production`, `SERVER_PEPPER` y `DATABASE_URL`. No publiques el
servicio con el pepper de desarrollo; configura `REVIEW_TOKENS`, `BROWSER_SCANNER_TOKEN` y ejecuta
las migraciones.

El navegador aislado es opcional. Se activa de forma explícita:

```powershell
$env:ENABLE_BROWSER_CHECKS = "true"
docker compose --profile browser up --build
```

El contenedor es de solo lectura, descarta capacidades, limita recursos, bloquea destinos privados,
POST y descargas, y no comparte red con la base de datos. En un despliegue expuesto debe añadirse
además un proxy de salida con pinning DNS.

## Endpoints principales

- `GET /health`
- `GET /metrics` (métricas agregadas para operaciones)
- `POST /api/v1/analyze/json`
- `POST /api/v1/analyze` (formulario, permite captura)
- `POST /api/v1/analyses/{id}/feedback`
- `GET /api/v1/analyses/{id}/stix` (exporta observables redactados en STIX 2.1)
- `GET /api/v1/reviews` (requiere token de revisión)
- `POST /api/v1/reviews/{id}/resolve` (requiere token de revisión)
- `GET /docs` (OpenAPI)

Ejemplo:

```powershell
Invoke-RestMethod http://localhost:8000/api/v1/analyze/json `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"message":"Su cuenta ha sido bloqueada. Verifique sus datos en https://banco-seguro.top"}'
```

## Aviso

Es software de apoyo y todavía no debe presentarse como un servicio de protección infalible. Un
dominio antiguo puede estar comprometido y uno oficial puede aparecer como texto engañoso. La
recomendación final siempre debe llevar al usuario a iniciar él mismo el contacto por un canal
oficial.
