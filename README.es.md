# QA Automation Agent — Framework AI-SDET e Ingeniería de Calidad

[![CI Quality Gates](https://github.com/v0idbrn/QA_Automation_Agent/actions/workflows/ci-quality-gates.yml/badge.svg?branch=main)](https://github.com/v0idbrn/QA_Automation_Agent/actions/workflows/ci-quality-gates.yml)
[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Pytest](https://img.shields.io/badge/tests-824%20passing-3ecf8e)](#suites-de-calidad)
[![License: MIT](https://img.shields.io/badge/license-MIT-4da3ff)](LICENSE)

Framework *local-first* de ingeniería de calidad que combina gates deterministas
de AI-SDET con un agente autónomo de QA web. Demuestra prácticas enterprise de
**evaluación de LLM, groundedness de RAG, seguridad de herramientas MCP,
testing de contratos API, auditoría de layout con Playwright, gobernanza de
datasets y gates de calidad en CI/CD** — sin enviar datos del objetivo a
servicios cloud.

La **Full-Spectrum v2.0** añade doce motores de auditoría orientados a cliente
(crawler acotado, profiler UX/a11y/Web-Vitals multi-viewport, seguridad
pasiva + integridad de checkout, fuzzing REST/GraphQL con SLAs de latencia,
localizadores auto-reparables, suites Playwright generadas, regresión visual
Pillow, análisis estático de APK, instalabilidad PWA, sondas de contrato CLI,
integridad RBAC/Workflow, auditoría de constraints SQLite/DDL, pruebas de
carga acotadas, inventario de tests/RTM/planificación) más un reporter
ejecutivo autónomo, un único CLI `python -m qa_agent` y un generador ATS de
CV consciente del workspace (`tools/cv_builder/`).

> 🇬🇧 English: [README.md](README.md).

---

## Qué contiene este repositorio

Dos capas en un mismo repositorio:

1. **Framework determinista AI-SDET** (`src/qa_agent/`)
   Evaluadores y validadores reutilizables que se ejecutan completamente
   offline. Las suites en `tests/evals`, `tests/security`, `tests/e2e`,
   `tests/data` y `tests/unit` los ejercitan con `pytest` y sin claves de API.
2. **Agente de QA autónomo** (`core/`, `main.py`, `gui.py`)
   Ciclo de auditoría orientado a empresa: descubrimiento, planificación por
   riesgo, ejecución acotada en navegador, captura de evidencia, análisis de
   fallos, hallazgos y un gate de calidad de cinco estados contra proyectos
   locales u objetivos web autorizados del mismo origen.

La capa AI-SDET es determinista por diseño: los mocks son el comportamiento por
defecto, las llamadas a modelos reales son opcionales y cada gate devuelve
resultados estructurados que CI puede verificar.

---

## Arquitectura

```text
QA_Automation_Agent
├── src/qa_agent/                  # Framework determinista AI-SDET + motores Full-Spectrum
│   ├── cli.py / __main__.py       # `python -m qa_agent audit|fuzz-api|gen-tests|
│   │                              #  visual-diff|eval-rag|audit-apk|audit-pwa|test-cli|
│   │                              #  audit-rbac|audit-workflow|audit-db|load-test|gen-test-plan`
│   ├── models.py                  # Contrato compartido Finding/Severity
│   ├── redaction.py               # Capa local `[REDACTED]` para URLs, textos, cabeceras
│   ├── crawler.py                 # Crawl BFS/DFS same-origin acotado: links, assets,
│   │                              # errores consola/página, fallos XHR, cadenas redirect
│   ├── ux_a11y_perf.py            # Viewports 360/390/768/1440, WCAG 2.1 AA,
│   │                              # tap targets, overlays, TTFB/FCP/LCP/CLS
│   ├── security_checkout.py       # Cabeceras/CSP/HSTS/CORS/cookies/sourcemaps/secretos
│   │                              # pasivos + integridad de carrito e idempotencia
│   ├── api_fuzzer.py              # Fuzzing frontera REST/OpenAPI, sondeos GraphQL,
│   │                              # p50/p95/p99 latencia vs SLA
│   ├── self_healing.py            # Recuperación de localizadores por similitud DOM ponderada
│   ├── test_generator.py          # Generador Pytest+Playwright E2E ejecutable
│   ├── visual_regression.py       # Tolerancia píxel Pillow, regiones ignoradas, diff PNG
│   ├── reporter.py                # HTML + Markdown + manifiesto SHA-256 autónomos
│   ├── llm_evals.py               # Adaptadores LLM mock/live, groundedness RAG,
│   │                              # semántica + contexto + agente + safety
│   ├── mcp_validator.py           # Esquema tool-call MCP + sanitizador entrada,
│   │                              # mapeado a OWASP LLM Top 10
│   ├── web_auditor.py             # Contratos HTTPX + consola Playwright + overflow móvil
│   ├── data_gates.py              # Esquema, nulos, duplicados, PII y drift etiquetas
│   │                              # gates sobre DataFrames pandas
│   ├── mobile_qa.py               # Análisis estático APK (permisos, componentes
│   │                              # exportados, debuggable, firmas, SDK) + auditoría
│   │                              # instalabilidad PWA (manifest, iconos, SW)
│   ├── desktop_cli_qa.py          # Sondas CLI acotadas (--help/--version/flag-desconocida)
│   │                              # + auditoría AST estática de escritorio
│   ├── functional_qa.py           # Auditoría matriz RBAC (sobre-privilegio, gaps) +
│   │                              # integridad workflow/máquina de estados (dead-ends, inalcanzables)
│   ├── db_qa.py                   # Parsing DDL (PK/FK/UNIQUE/NOT NULL), detección
│   │                              # money-type float, auditoría PRAGMA SQLite (huérfanos, integridad)
│   ├── performance_qa.py          # ThreadPoolExecutor runs acotados, p50/p95/p99
│   │                              # latencia, gates error-rate/5xx
│   └── test_management.py         # Descubrimiento AST tests (Python/JS), cobertura RTM,
│                                  # planes basados en riesgo, salud JUnit XML
├── tools/cv_builder/              # Generador ATS CV & Propuesta consciente del workspace
│   ├── workspace_scanner.py       # Descubrimiento sibling-repos, parsing manifiestos, AST tests
│   ├── presets.py                 # 5 presets de rol + perfil privado (PII desde env/archivo)
│   ├── jd_tailor.py               # ATS keyword match %, re-rank bullets/proyectos, LLM tailor
│   ├── renderers.py               # reportlab PDF + python-docx DOCX (one-page/detailed)
│   └── cli.py                     # `python -m tools.cv_builder --preset all --jd job.txt --ai`
├── tests/
│   ├── evals/                     # LLM/RAG + semántico/contexto/agente/safety
│   ├── security/                  # Guardrails MCP
│   ├── e2e/                       # Audits HTTPX/Playwright + suite live Workhorse
│   ├── data/                      # Gates gobernanza datasets
│   ├── unit/                      # Tests offline puros para cada motor (+ cv_builder)
│   ├── fixtures/vulnerable_saas_fixture.py  # Objetivo local con defectos sembrados
│   └── test_*.py                  # Suite regresión agente autónomo legacy
├── core/                          # Motores agente autónomo (reutilizados, no reescritos)
│   ├── discovery.py               # Perfil proyecto solo lectura
│   ├── requirements_engine.py     # Requisitos explícitos / inferidos / desconocidos
│   ├── risk_engine.py             # Scoring riesgo siete ejes
│   ├── planner.py                 # Requisitos → riesgos → plan → casos test
│   ├── orchestrator.py            # Máquina estados acotada + executor + decisiones
│   ├── live_session.py            # Sesiones Playwright acotadas
│   ├── quality_gate.py            # PASS / WARN / FAIL / BLOCKED / NEEDS_HUMAN
│   ├── evidence.py                # Entradas evidencia + manifiesto ejecución
│   ├── redaction.py               # Capa central scrubbing secretos/PII
│   └── report_builder.py          # Markdown, HTML, JSON, export Jira
├── samples/demo_site/             # Objetivo sintético con hallazgos deliberados
├── scripts/                       # Demo runner y build exe Windows
├── .github/workflows/
│   └── ci-quality-gates.yml       # Gate push/PR Python 3.11/3.12
├── cv_metrics.json                # Métricas legibles por máquina
├── pyproject.toml                 # Metadatos paquete qa_agent instalable
├── pytest.ini                     # Ruta src/ + descubrimiento tests
├── main.py                        # CLI: discover | plan | run | report | validate
└── gui.py                         # Centro control escritorio sobre la misma CLI
```

### Flujo de ejecución

```text
                  ┌───────────────── gates deterministas AI-SDET ───────────────┐
commit / PR ───► │ LLM+RAG → seguridad MCP → API+Playwright → datos           │ ───► pytest
                  └──────────────────────────────────────────────────────────────┘

objetivo ───► discover ───► requisitos ───► riesgo ───► plan ───► ejecutar
                                                                      │
                informe ◄── quality gate ◄── hallazgos ◄── analizar ◄┘
```

---

## Suites de calidad

`pytest.ini` hace importable `src/` y limita el descubrimiento a `tests/`. La
suite completa del repositorio suma **824 tests en verde** en unos 60 segundos,
offline salvo las auditorías de navegador contra el fixture local.

| Suite | Tests | Cobertura |
|---|---:|---|
| `tests/unit/test_models_redaction.py` | 23 | Contrato `Finding`, orden severidad, redacción central |
| `tests/unit/test_crawler_helpers.py` | 40 | Normalización URL, same-origin, assets, extracción links/assets, límites config |
| `tests/unit/test_ux_a11y_perf.py` | 67 | Matemática color, defectos layout, WCAG AA, presupuestos Web Vitals |
| `tests/unit/test_security_checkout.py` | 63 | Cabeceras, CSP, cookies, CORS, secretos, stacktraces, carrito/idempotencia |
| `tests/unit/test_api_fuzzer.py` | 53 | Catálogo payloads, parsing OpenAPI, clasificación, GraphQL, latencia/SLA |
| `tests/unit/test_self_healing_generator.py` | 43 | Scoring similitud, parches selectores, corrección módulo generado |
| `tests/unit/test_visual_regression.py` | 25 | Tolerancia píxel, regiones ignoradas, bbox/shift, output diff y side-by-side |
| `tests/unit/test_reporter_cli.py` | 35 | Escape HTML/Markdown, hashing manifiesto, parsing CLI y códigos salida |
| `tests/unit/test_full_spectrum_qa.py` | 53 | Mobile/APK, PWA, CLI/desktop, RBAC, workflow, DB, carga, gestión tests |
| `tests/unit/test_cv_builder.py` | 45 | Scanner workspace, presets, ATS matching, seguridad PII, mock LLM, PDF/DOCX |
| `tests/evals/test_llm_rag.py` | 28 | Adaptadores LLM, groundedness RAG, salida estructurada, regresión prompts, presupuestos |
| `tests/evals/test_semantic_evals.py` | 60 | Similitud TF-IDF, precisión/recall contexto, trazas multi-agente, seguridad, coste |
| `tests/security/test_mcp_guardrails.py` | 55 | Esquemas tools, sanitización, traversal, command injection, SSRF, prompt injection |
| `tests/e2e/test_web_api_audit.py` | 20 | Contratos HTTP, envelopes error, errores consola, overflow móvil, transporte ASGI |
| `tests/e2e/test_workhorse_live.py` | 22 | Crawl/UX/seguridad/fuzz/generación/informe live contra fixture |
| `tests/data/test_dataset_quality.py` | 21 | Esquema, nulos, duplicados, PII, drift etiquetas |
| Suite legacy agente (`tests/test_*.py`) | 171 | Descubrimiento, planificación, orquestación, seguridad, informes, packaging |

### 1. Evaluación de LLM y RAG

`src/qa_agent/llm_evals.py` incluye:

- `MockLLMAdapter` — respuestas deterministas y offline indexadas por prompt;
  es el adaptador por defecto en todos los tests.
- `OpenAICompatibleAdapter` — adaptador live opcional que usa
  `OPENAI_API_KEY` o `GROQ_KEY` y una base URL compatible con OpenAI.
- `evaluate_groundedness()` — soporte por claim contra los chunks recuperados,
  con rechazo explícito de cifras que no aparecen en la fuente.
- `validate_structured_output()` — parseo JSON más validación estricta con
  Pydantic (`extra="forbid"` en los esquemas de test).
- `run_conversation()` — regresión multi-turno con aserciones
  `must_contain` / `must_not_contain`.
- `assert_within_budget()` — umbrales de latencia y tokens.

La suite cubre respuestas fundamentadas, entidades inventadas, cifras
fabricadas, grounding parcial, JSON con fences, campos faltantes o extra,
rangos inválidos, regresiones multi-turno, fallos de presupuesto, manejo de
credenciales y determinismo del mock. No se usa red.

### 2. Seguridad de herramientas MCP

`src/qa_agent/mcp_validator.py` valida objetos `ToolCall` estilo MCP contra una
`ToolPolicy` declarada y devuelve registros `Violation` estructurados.

| Control | Ejemplos bloqueados | OWASP LLM Top 10 |
|---|---|---|
| Path traversal | `../`, `%2e%2e/`, `..\`, rutas absolutas | LLM05 Improper Output Handling |
| Command injection | `;`, `&&`, `\|\|`, `\|`, `$()`, backticks, redirecciones, saltos de línea | LLM06 Excessive Agency |
| SSRF | loopback, RFC1918, link-local, `169.254.169.254`, hosts de metadata, IPs decimales/hex, userinfo | LLM06 Excessive Agency |
| Esquemas inseguros | `file:`, `gopher:`, `ftp:` | LLM06 Excessive Agency |
| Prompt injection | overrides directos, exfiltración del system prompt, marcadores HTML/rol indirectos | LLM01 Prompt Injection |
| Datos sensibles | argumentos con forma de API key, bearer token o password | LLM02 Sensitive Information Disclosure |
| Abuso de esquema | tools/argumentos desconocidos, requeridos ausentes, tipos incorrectos, inputs enormes | LLM06 Excessive Agency |

Las entradas se normalizan con NFKC y se decodifican percent-encoding hasta tres
veces antes de inspeccionarlas. Los caracteres de control se eliminan. Una
llamada solo se permite si coincide con el esquema declarado y no produce
ninguna violación.

### 3. Contratos API y auditoría web con Playwright

`src/qa_agent/web_auditor.py` expone:

- `audit_json_contract()` — código de estado, content type
  `application/json`, parseo JSON y validación de esquema Pydantic vía HTTPX.
- `audit_error_response()` — envelope estable `{error, message}`, estado
  correcto y ausencia de traceback/stack/exception filtrado.
- `audit_web_page()` — sesión Chromium acotada que recopila errores de
  `console`, errores de página no capturados y overflow horizontal en un
  viewport móvil de **390×844**.

La suite E2E usa un `ThreadingHTTPServer` local con endpoints limpios, ruidosos,
malformados y fallidos, además de una app ASGI mínima ejecutada mediante
`httpx.ASGITransport`. Las auditorías de navegador arrancan y detienen Playwright
dentro del test para no filtrar event loops a la suite async del agente. Los
fallos de transporte devuelven un `ApiContractResult` estructurado en lugar de
lanzar una excepción, de modo que un endpoint caído no rompe el pipeline.

### 4. Gobernanza de datasets y drift

`src/qa_agent/data_gates.py` valida DataFrames de pandas y devuelve un
`DatasetReport` en lugar de abortar en el primer problema:

- columnas requeridas y contrato de dtypes;
- ratio de nulos por columna;
- ratio de registros duplicados;
- detección de PII para email, teléfono, SSN, tarjetas válidas por Luhn, API
  keys e IPv4;
- drift de distribución de etiquetas con distancia de variación total;
- categorías inesperadas o ausentes.

Los valores de PII nunca se copian al informe: solo se conservan recuentos por
columna y categoría. Los frames sintéticos mantienen la suite determinista y
segura.

---

## Inicio rápido

Requisitos: **Python 3.11+** y runtime de Node.js para los navegadores de
Playwright.

```bash
python -m venv .venv

# Windows
.venv\Scripts\pip install -r requirements.txt
.venv\Scripts\playwright install chromium

# POSIX
source .venv/bin/activate
pip install -r requirements.txt
playwright install chromium
```

Instala el paquete reutilizable para importarlo fuera de pytest:

```bash
# Windows
.venv\Scripts\pip install -e .

# POSIX
pip install -e .
```

Ejecuta el gate completo:

```bash
.venv\Scripts\python -m pytest -q
```

Ejecuta una suite concreta:

```bash
.venv\Scripts\python -m pytest tests/evals -q
.venv\Scripts\python -m pytest tests/security -q
.venv\Scripts\python -m pytest tests/e2e -q
.venv\Scripts\python -m pytest tests/data -q
```

### CLI del agente autónomo

```bash
python main.py discover <target>          # perfil de proyecto de solo lectura
python main.py plan <target>              # requisitos + riesgos + plan
python main.py run <target>               # ciclo de auditoría acotado
python main.py report <run-dir>           # refrescar/resumir una ejecución
python main.py validate <run-dir>         # crash recovery + veredicto del gate
```

Ejemplo sobre el sitio sintético incluido:

```bash
# Terminal 1: servidor local acotado
cd samples/demo_site
../../.venv/Scripts/python server.py --port 8000 --max-requests 200

# Terminal 2: auditoría
cd ../..
.venv/Scripts/python main.py run samples/demo_site --profile safe \
    --url http://127.0.0.1:8000 --output reports/demo_run
```

O ejecuta la demo completa, incluido el ciclo de vida del servidor:

```bash
.venv/Scripts/python scripts/demo.py --port 8000
```

Flags habituales: `--profile safe|standard|deep|ci`, `--risk low|medium|high`,
`--browser chromium|firefox|webkit`, `--headed`/`--headless`, `--output DIR`,
`--budget`, `--scope`, `--min-coverage`, `--dry-run`, `--allow-external`.

Códigos de salida: `0` pass/pass-with-warnings · `1` gate fail o interrumpido ·
`2` escalado/necesita humano/error de configuración · `130` interrupción de
teclado.

### CLI de auditoría Workhorse (Full-Spectrum v2.0)

La suite de motores de auditoría también se expone desde el paquete instalable,
sin depender del bucle autónomo:

```bash
python -m qa_agent audit <url> --out-dir reports/audit            # crawl + UX + seguridad + informe
python -m qa_agent fuzz-api <url|openapi.json> --endpoint /api/validate --sla-ms 500
python -m qa_agent gen-tests <url> --out generated_tests --max-pages 3
python -m qa_agent visual-diff baseline.png current.png --out reports/visual/diff.png
python -m qa_agent eval-rag dataset.json --min-score 0.6 --min-recall 0.8

# Añadidos Full-Spectrum v2.0:
python -m qa_agent audit-apk <path/to/app.apk> --out-dir reports/apk
python -m qa_agent audit-pwa <build-dir|https://url> --out-dir reports/pwa
python -m qa_agent test-cli -- python -m mycli --out-dir reports/cli
python -m qa_agent audit-rbac matrix.json --out-dir reports/rbac
python -m qa_agent audit-workflow transitions.json --out-dir reports/workflow
python -m qa_agent audit-db <schema.sql|app.db> --out-dir reports/db
python -m qa_agent load-test https://api.example.com --requests 50 --concurrency 10 --sla-ms 800
python -m qa_agent gen-test-plan <repo-root> --requirements reqs.json --junit junit.xml
```

Cada comando imprime un resumen JSON y escribe artefactos en `--out-dir`.
`audit` genera `audit_report.html` (informe ejecutivo autónomo), `bug_report.md`,
`manifest.json` con SHA-256 y evidencias. Códigos de salida: `0` gate superado ·
`1` hallazgos bloqueantes · `2` el comando no pudo ejecutarse.

El fixture `tests/fixtures/vulnerable_saas_fixture.py` sirve un SaaS local con
defectos deliberados (a11y, contraste, overflow móvil, cookie wall, enlaces y
assets roto, errores de consola, cookies débiles, cabeceras ausentes, secreto
cliente, 500 con SQL, XSS reflejado, checkout no idempotente y GraphQL abierto).

### Centro de control de escritorio (Windows)

Haz doble clic en `QA_Agent.bat` (o ejecuta `python gui.py`). La GUI compone los
mismos comandos de la CLI, muestra la consola en vivo, permite detener una
ejecución y renderiza el informe válido más reciente. No introduce ninguna ruta
de ejecución alternativa.

### Bundle Windows autónomo

```bash
.venv/Scripts/python scripts/build_exe.py
```

Genera `dist/QA_Agent/` con `QA_Agent.exe` (ventana) y `qa-agent.exe` (consola).
Instala los navegadores una vez en el equipo destino con
`qa-agent.exe install-browsers`.

---

## Gates de CI/CD

`.github/workflows/ci-quality-gates.yml` se ejecuta en cada push y pull request
a `main` (y de forma manual) sobre Python 3.11 y 3.12:

1. checkout y configuración de Python con caché de pip;
2. instalación de `requirements.txt` y del paquete editable `qa_agent`;
3. verificación de consistencia con `pip check`;
4. instalación de Chromium con dependencias de sistema vía Playwright;
5. ejecución de **la suite completa** con salida JUnit;
6. publicación de `cv_metrics.json` y del informe JUnit como artefactos.

Un test fallido hace fallar el workflow, por lo que la suite puede usarse
directamente como check obligatorio en branch protection. El badge superior
refleja la última ejecución en `main`.

`cv_metrics.json` es la instantánea legible por máquina del gate local:

```json
{
  "total_tests": 824,
  "modules": [
    "api_fuzzer",
    "cli",
    "crawler",
    "data_gates",
    "db_qa",
    "desktop_cli_qa",
    "functional_qa",
    "llm_evals",
    "mcp_validator",
    "mobile_qa",
    "performance_qa",
    "reporter",
    "security_checkout",
    "self_healing",
    "test_generator",
    "test_management",
    "ux_a11y_perf",
    "visual_regression",
    "web_auditor"
  ],
  "cli": [
    "audit",
    "audit-apk",
    "audit-db",
    "audit-pwa",
    "audit-rbac",
    "audit-workflow",
    "eval-rag",
    "fuzz-api",
    "gen-test-plan",
    "gen-tests",
    "load-test",
    "test-cli",
    "visual-diff"
  ],
  "stack": [
    "Python",
    "Pytest",
    "Playwright",
    "Pydantic",
    "HTTPX",
    "Pillow",
    "GitHub Actions",
    "reportlab",
    "python-docx"
  ]
}
```

---

## Capacidades enterprise del agente

- Descubrimiento de proyecto de solo lectura: framework, rutas, APIs,
  formularios, tests, autenticación y flags de riesgo.
- Requisitos clasificados `explicit` / `inferred` / `unknown`; las inferencias
  nunca se presentan como confirmadas.
- Scoring de riesgo en siete ejes y planificación priorizada con IDs estables.
- Trazabilidad: `Requisito → Riesgo → Test → Ejecución → Evidencia → Hallazgo →
  Quality Gate`.
- Ejecución acotada: mismo origen por defecto y presupuestos de páginas,
  requests, profundidad, runtime y tests; sin auto-reset al agotarse.
- Ejercicio defensivo de formularios y heurísticas de accesibilidad.
- Interceptación de APIs para 4xx/5xx, JSON malformado y content types inválidos.
- Taxonomía de 12 tipos de fallo con reintentos solo para fallos transitorios
  (máximo tres por firma); producto/auth/config/test/datos nunca se reintentan.
- Detección de flaky: la oscilación PASS/FAIL se reporta sin promoverla a bug.
- Deduplicación de hallazgos por fingerprint de seis campos con confianza
  LOW/MEDIUM/HIGH.
- Gate de calidad de cinco estados y motor de cobertura de requisitos.
- Escalado humano con motivo, intentos, evidencia e input requerido.
- Crash recovery: una ejecución interrumpida termina como `INTERRUPTED` /
  `BLOCKED`.
- Escrituras atómicas de artefactos y redacción central en logs e informes.
- Informes Markdown, HTML y JSON, más export compatible con Jira.

### Modelo de seguridad

Los valores por defecto fallan cerrados:

- **Descubrimiento de solo lectura** — nunca escribe en el objetivo.
- **Deny unknown** — URLs de otro origen y rutas destructivas se rechazan salvo
  autorización explícita.
- **Ejecución acotada** — cada acción de red consume presupuesto.
- **Sin payloads destructivos** — las comprobaciones de formularios son
  sintéticas e inocuas.
- **Sin secretos en logs** — una capa central de redacción protege logs,
  evidencia, manifiestos e informes.
- **Frontera LLM** — un LLM puede proponer, pero las propuestas se validan y
  solo el executor autorizado puede ejecutarlas.

Prueba únicamente sistemas propios o con permiso escrito.

---

## Stack

- Python 3.11+
- Pytest (+ `pytest-asyncio`)
- Playwright (Chromium) y HTTPX
- Pydantic v2
- pandas
- Pillow (regresión visual)
- Jinja2 informes
- GitHub Actions
- GUI tkinter y bundle PyInstaller (opcionales)
- reportlab (rendering PDF) y python-docx (rendering DOCX)

## Principios de diseño

- **Offline-first:** CI no necesita credenciales de modelos ni servicios de
  terceros.
- **Determinista:** respuestas mock y fixtures fijos hacen reparables los fallos.
- **Resultados estructurados:** los gates devuelven objetos tipados, no texto.
- **Autonomía acotada:** los límites y el escalado explícito forman parte de la
  arquitectura.
- **Evidencia antes que veredictos:** los hallazgos heurísticos requieren
  confirmación humana.

## Limitaciones

- La groundedness de RAG usa soporte léxico por claim, no un juez semántico; es
  un gate de regresión rápido, no un sustituto de revisión humana.
- El drift de etiquetas mide cambio de distribución, no causalidad de calidad.
- Las comprobaciones de accesibilidad son heurísticas y no certifican WCAG.
- La cobertura mide el mapeo requisito-test, no cobertura de código.
- El crawling está acotado; las SPA con mucho JavaScript pueden requerir más
  presupuesto.
- No se incluyen integraciones cloud. La evaluación LLM live es opcional y
  requiere credenciales de entorno.

## Licencia

MIT. Ver [LICENSE](LICENSE). Copyright (c) 2026 Gaetano (v0idbrn).