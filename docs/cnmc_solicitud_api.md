# Solicitud de Información y Acceso Técnico al Registro de Alias (Circular 1/2026 CNMC)

**Destinatario:** Comisión Nacional de los Mercados y la Competencia (CNMC) — Dirección de Telecomunicaciones y del Sector Audiovisual  
**Asunto:** Consulta técnica sobre el portal de consulta pública y acceso programático (API/Open Data) al Registro de Identificadores de Remitente (Alias) para SMS/MMS/RCS  
**Referencia:** Circular 1/2026, de 11 de marzo, de la CNMC (BOE-A-2026-7043)  
**Fecha:** 19 de agosto de 2026  

---

### 1. Presentación de la entidad solicitante
El presente escrito se remite en nombre del equipo de desarrollo e investigación del proyecto **Alerta Clara**, una iniciativa académica y de código abierto sin ánimo de lucro orientada a la protección activa de la ciudadanía frente a estafas digitales, suplantaciones de identidad bancaria y ataques de smishing en España.

La arquitectura de Alerta Clara implementa un motor de análisis auditable con preservación de la privacidad que contrasta remitentes, enlaces y contenido de comunicaciones sospechosas contra registros oficiales, fuentes de inteligencia de amenazas y evidencias técnicas contrastables.

---

### 2. Contexto y motivación técnica
Con la aprobación de la **Circular 1/2026 de la CNMC**, que regula la creación del **Registro de Identificadores de Remitente (Alias)** para servicios de mensajería interpersonal SMS/MMS/RCS, y ante la próxima entrada en vigor plena de las obligaciones de comprobación y bloqueo el **15 de septiembre de 2026**, el registro público de alias se consolida como una pieza clave para la defensa preventiva del consumidor.

Nuestra plataforma procesa mensajes en tiempo real y precisa validar si los identificadores alfanuméricos empleados en mensajes comerciales o institucionales corresponden fehacientemente a los titulares oficiales de las entidades emisoras.

---

### 3. Consultas y peticiones técnicas
Con el fin de integrar la consulta de alias en el pipeline de análisis de Alerta Clara desde el primer día de disponibilidad del portal público, solicitamos respetuosamente información sobre los siguientes aspectos:

1. **Disponibilidad de interfaz programática (API):**
   - ¿Tiene previsto la CNMC habilitar un endpoint REST (JSON) para la consulta de identificadores de remitente registrados?
   - En caso afirmativo, ¿cuáles serán los requisitos de autenticación (clave de API, certificado de sede electrónica o acceso público no autenticado)?

2. **Acceso a volcados de datos abiertos (Open Data / Data Snapshots):**
   - ¿Se publicará un volcado periódico (diario/semanal en formatos estándar como JSON, CSV o Parquet) del censo de alias activos, su titular, NIF/CIF y fecha de asignación para su descarga y sincronización local con TTL?

3. **Estructura y campos del registro público:**
   - ¿Qué campos específicos estarán disponibles en las respuestas (ej. alias, razón social del titular, CIF/NIF, categoría sectorial, fecha de activación/caducidad, estado del alias)?

4. **Colaboración con proyectos de investigación y protección ciudadana:**
   - ¿Existe un canal de contacto técnico o programa piloto para herramientas universitarias y proyectos de defensa del consumidor que deseen validar integraciones previas al 15 de septiembre de 2026?

---

### 4. Datos de contacto y canal de respuesta
Agradecemos de antemano la atención y quedamos a su entera disposición para cualquier aclaración técnica o reunión preliminar.

- **Proyecto:** Alerta Clara (Investigación y Protección contra el Fraude Digital)
- **Repositorio y documentación:** https://github.com/nathan/alerta-clara *(o URL del repositorio)*
- **Correo de contacto:** *(contacto institucional / universidad)*
