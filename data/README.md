# Datos para el clasificador

El entrenamiento local combina [SpaPhish v5](https://data.mendeley.com/datasets/hz2d6gz7pc/5),
un corpus de 1.395 correos en español (731 phishing y 664 legítimos), con un pequeño corpus de
300 SMS en español para adaptación de dominio. SpaPhish está publicado con licencia CC BY 4.0 y
el corpus SMS se distribuye bajo CC BY-SA 4.0. Los ficheros originales se descargan en
`data/external/`, una ruta ignorada por Git.

Para reproducirlo:

```powershell
New-Item -ItemType Directory -Force data\external | Out-Null
Invoke-WebRequest `
  -Uri "https://data.mendeley.com/public-files/datasets/hz2d6gz7pc/files/f796c8e2-3768-4c2d-8b73-48f0d7771de5/file_downloaded" `
  -OutFile "data\external\spaphish_v5.csv"
.\.venv\Scripts\python.exe -m app.ml_training
```

El entrenamiento reemplaza URLs por `[ENLACE]` y aplica la redacción local antes de crear el
modelo. No se guardan en el artefacto nombres, teléfonos, correos ni URLs activas. La colección
es de correo electrónico, no de SMS; por eso el modelo se usa como señal auxiliar y no como
veredicto único.

La procedencia y el hash SHA-256 de los archivos descargados quedan registrados en
`models/phishing_tfidf.metrics.json`.

El corpus SMS es pequeño y de investigación; se utiliza para que el modelo vea el formato de
mensajes cortos, no como única fuente de verdad. Las reglas y la revisión de casos siguen siendo
necesarias antes de usar el clasificador en producción.
