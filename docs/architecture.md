# Arquitectura del MVP

## Objetivo y audiencia

Alerta Clara ayuda a una persona —especialmente a quien tiene poca soltura digital— a detenerse
antes de pulsar un enlace, compartir un código o transferir dinero. La página tiene un único trabajo:
convertir un mensaje sospechoso en una acción prudente y comprensible.

## Flujo

```text
Entrada web/API
      │
      ▼
Redacción + QR/OCR local ─► extracción local + modelo opcional
      │                            │
      └────────────────────────────┘
                   │ hechos estructurados
                   ▼
 señales locales + reputación + correlación de artefactos
                   │
                   ├──── análisis léxico de URL (sin red)
                   ├──── feeds locales versionados (sin consulta remota por petición)
                   ├──── RDAP (3 s)
                   ├──── TLS (3 s)
                   ├──── redirecciones (3 s)
                   └──── navegador aislado opcional
                   │
                   ▼
             motor de reglas
          ┌────────┴─────────┐
          ▼                  ▼
       ESTAFA        NO PUEDO CONFIRMARLO
          └────────┬─────────┘
                   ▼
    redacción clara opcional (sin cambiar nivel ni acción)

En paralelo a la decisión de riesgo, un clasificador local estima el tipo de mensaje (`phishing`,
`spam`, `transaccional`, `personal` o `desconocido`). Esa etiqueta es orientativa y nunca puede
convertir `NO PUEDO CONFIRMARLO` en una afirmación de legitimidad.
```

## Decisiones que mejoran la propuesta inicial

1. **El modelo nunca puntúa ni cambia el nivel.** La combinación «reglas duras + valoración del
   modelo» deja un grado de decisión difícil de reproducir. Aquí el score y las reglas producen el
   veredicto; el modelo solo extrae hechos y mejora la prosa.
2. **Las operaciones web se tratan como hostiles.** Las comprobaciones ligeras limitan puertos,
   saltos, dominios y tiempos. El navegador completo vive en un sidecar desechable sin red hacia
   Postgres/Redis, bloquea destinos privados y métodos con efecto. En producción aún requiere un
   proxy de salida con pinning DNS para cerrar ataques de rebinding.
3. **La lista blanca es provisional y no contiene teléfonos sin verificar.** Inventar o copiar números
   desactualizados sería peor que no tenerlos. Deben validarse con cada entidad y registrarse con
   fecha y fuente antes de activar reglas de teléfono oficial.
4. **SQLite es solo una comodidad local.** El mismo esquema funciona con Postgres en Compose. En
   producción la configuración rechaza SQLite.
5. **La interfaz no usa verde ni porcentajes.** El estado neutro es ámbar y expresa incertidumbre.
   Rojo queda reservado a señales suficientes de estafa.
6. **Una allowlist solo aporta contexto.** Un dominio oficial o una plataforma compartida puede
   neutralizar ruido técnico concreto, pero nunca produce un veredicto de legitimidad ni anula una
   petición peligrosa.
7. **La inteligencia externa se descarga fuera de la petición.** Cada snapshot conserva proveedor,
   versión, checksum, fecha, TTL y política. Al caducar deja de puntuar; una fuente de confianza alta
   o el consenso de dos fuentes es necesario para una regla dura.
8. **Una coincidencia de campaña no nace de una sola frase.** Se almacenan artefactos por tipo; los
   teléfonos e IBAN solo como HMAC. Se exigen dos tipos coincidentes y la campaña debe estar
   confirmada para ser evidencia concluyente. La similitud textual de campañas sin confirmar solo
   aporta una pista.
9. **La superficie pública tiene presupuesto.** Cada IP tiene límites de análisis y feedback, las
   operaciones costosas esperan en cola y las respuestas incluyen cabeceras de seguridad. Las
   métricas agregadas no contienen cuerpo, URL, remitente ni UUID.
10. **Las capturas requieren consentimiento explícito para salir.** QR y OCR local funcionan
    localmente; el envío de imagen a visión externa solo se activa con
    `ALLOW_EXTERNAL_IMAGE_ANALYSIS=true`.

## Umbral actual

- Cualquier `hard_rule` produce `ESTAFA`.
- Sin regla dura, 70 puntos acumulados producen `ESTAFA`.
- Todo lo demás produce `NO PUEDO CONFIRMARLO`.

Un tipo de señal solo aporta su peso una vez, aunque aparezca en varios enlaces. Esto evita que tres
URLs con el mismo indicio inflen artificialmente la puntuación. Solo las señales con estado `hit`
pueden puntuar o disparar una regla dura; `error` y `timeout` quedan registrados con peso cero.

El score se persiste indirectamente mediante las señales, pero no se muestra al usuario. Antes de
cambiar pesos o umbrales hay que ejecutar el golden set y versionar el cambio en `RULESET_VERSION`.

## Datos y retención

- `user_hash`: HMAC-SHA256 con `SERVER_PEPPER`; nunca se guarda el identificador original.
- `body_redacted`: texto con identificadores sensibles sustituidos.
- Capturas: permanecen en memoria durante la petición y no se escriben en disco.
- Valores de señales: se redactan recursivamente antes de persistirlos.
- Artefactos públicos: solo dominios y plantillas sin valores de query. Teléfonos e IBAN se guardan
  como HMAC-SHA256 con `SERVER_PEPPER`.
- Señales, campañas y fingerprints: se conservan para evaluación y detección de recurrencias.
- `model_version` y `ruleset_version`: se guardan en cada veredicto.
- `purged_at`: deja constancia de cuándo se eliminó el contenido sujeto a retención.

El proceso de la aplicación ejecuta una purga al arrancar y después cada
`RETENTION_PURGE_INTERVAL_SECONDS`. Al vencer `BODY_RETENTION_HOURS` elimina cuerpo, seudónimo,
remitente, URLs y marcadores textuales; conserva clasificación, señales y veredicto. Es idempotente y
se puede probar directamente mediante `purge_expired_message_data`.

## Trazabilidad y evaluación

Cada analizador persiste estado, fuente, versión, latencia, valor redactado y evidencia textual. El
veredicto persiste además el score y trazas de evidencia dura, score ponderado y supresiones por
infraestructura compartida. Así se puede reproducir por qué cambió un resultado entre rulesets.

`python -m app.evaluation` ejecuta el golden set sin red ni modelo, comprueba fugas de campaña,
duplicados y orden temporal, calcula métricas por idioma/tipo/señuelo/split y aplica umbrales
versionados. Los casos sintéticos actuales son una semilla de regresión, no una estimación de
rendimiento real. `python -m app.dataset_import` transforma CSV públicos y redacta sus mensajes.

La retrobúsqueda compara casos antiguos dudosos con feeds vigentes y campañas confirmadas. Solo
crea `review_items`; nunca cambia el veredicto. La cola administrativa usa tokens con roles,
registra consultas y resoluciones en `audit_events`, y puede confirmar una campaña para análisis
futuros.

## Qué falta antes de un piloto

En orden:

1. Ampliar el golden set hasta 200 mensajes reales, revisados y separados temporalmente.
2. Verificación manual y trazable de dominios y teléfonos oficiales.
3. Registro de consentimiento, política de privacidad y revisión jurídica de RGPD.
4. Revisión jurídica y de licencia de cada dataset/feed antes de redistribuirlo.
5. Proxy de salida con pinning DNS y límites de transferencia para el sidecar de navegador.
6. Adaptador de Telegram para probar el core; los endpoints actuales ejecutan el pipeline en un hilo
   aislado y no mantienen un worker RQ sin consumidor.
7. Trámite y adaptador de WhatsApp Cloud API; webhook que solo encola y responde 200.

## OpenAI

La integración usa salida estructurada con Pydantic y la Responses API. El snapshot predeterminado
es `gpt-5.4-nano-2026-03-17`: admite imagen de entrada y Structured Outputs y está orientado a tareas
de extracción de alto volumen. La aplicación sigue funcionando en modo local si la clave no existe
o si falla una extracción de texto. Las capturas requieren, además, consentimiento explícito para
enviarse a un proveedor de visión.
