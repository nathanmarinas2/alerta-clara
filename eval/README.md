# Golden set

`golden_set.jsonl` es la puerta de calidad del motor de reglas. Cada línea contiene un caso
independiente con etiqueta interna, veredicto público esperado y las señales que obligatoriamente
deben activarse.

Los ejemplos iniciales son sintéticos y no contienen datos personales. Cada caso incluye idioma,
tipo, señuelo, campaña, fecha, fuente y split. Antes de un piloto deben ampliarse hasta 200 casos
revisados —100 estafas y 100 mensajes legítimos—.

Ejecuta:

```powershell
.\.venv\Scripts\python.exe -m app.evaluation
```

El comando falla con código distinto de cero si baja el recall mínimo, sube la tasa máxima de falsas
alarmas, disminuye el acuerdo esperado, desaparece una señal requerida, se filtra una campaña entre
splits, aparece un duplicado cruzado o se rompe el corte temporal. El informe JSON añade métricas por
idioma, tipo de estafa, señuelo y split.

Para importar un CSV público sin arrastrar columnas de números de destino u otros identificadores:

```powershell
.\.venv\Scripts\python.exe -m app.dataset_import datos.csv eval\publico.jsonl `
  --profile generic --source nombre-del-dataset --validation-after 2026-01-01
```

También existen los perfiles `ncsu` e `imc25`. El importador redacta el texto, deriva un identificador
de campaña cuando falta y asigna el split por campaña. Con un corte temporal, las campañas que
atraviesan la frontera se ponen en cuarentena y no se exportan: conservarlas filtraría ejemplos casi
idénticos entre ajuste y validación. Revisa siempre la licencia y las etiquetas antes de incorporar el
resultado al golden set versionado.

## Fuentes y Atribución de Datasets

- **SMS Phishing Dataset (Mishra & Soni, Mendeley Data, CC BY 4.0)**:
  - Referencia: *Mishra, A. & Soni, D. (2022). SMS Phishing Dataset. Mendeley Data, V1, doi: 10.17632/f45bkkt8pr.1*.
  - Licencia: Creative Commons Attribution 4.0 International (CC BY 4.0).
  - Uso: Entrenamiento de clasificadores auxiliares de estructura de smishing.
- **MIMICS-3500 (Proyecto LUCIA / Universidad de León / INCIBE)**:
  - Referencia: *Engineering Applications of Artificial Intelligence vol. 163 (2026)*. Dataset multi-clase de smishing con 13 categorías finas en español de España. Fuente de referencia para evaluación académica y taxonomía de fraude.

