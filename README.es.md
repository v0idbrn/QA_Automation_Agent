# Ingeniero de QA Autónomo & Agente de Reporte de Bugs (Enterprise Edition)

> 🇬🇧 English ([README.md](README.md)) | 🇪🇸 Español (este archivo)

Agente de QA autónomo y *local-first* que ejecuta un ciclo de auditoría completo —
**DESCUBRIMIENTO → REQUISITOS → RIESGO → PLANIFICACIÓN → GENERACIÓN DE TESTS →
EJECUCIÓN → EVIDENCIA → ANÁLISIS DE FALLOS → REINTENTOS → HALLAZGOS → GATE DE
CALIDAD → INFORME → ESCALADO HUMANO** — contra un proyecto local o un objetivo
web dentro del alcance declarado, sin enviar contenido de páginas, capturas,
logs ni informes fuera del entorno local.

Este es un **asistente de auditoría que amplifica a los ingenieros de QA**. No
los reemplaza: los hallazgos heurísticos son evidencia, no veredictos, y las
situaciones ambiguas o peligrosas escalan a un humano por diseño.

## Legal y cumplimiento

- Licencia: MIT. Ver `LICENSE`.
- Copyright (c) 2026 Gaetano (v0idbrn).
- Ejecuta esta herramienta únicamente contra objetivos que te pertenezcan o
  para los que tengas permiso explícito por escrito. Aceptas plena
  responsabilidad por el cumplimiento de leyes, contratos y términos de
  servicio aplicables.

## Problema que resuelve

Los equipos necesitan repetir ciclos de QA básicos (enlaces rotos, consola,
accesibilidad, API, formularios) en cada cambio, pero el tiempo humano es
escaso. Este agente ejecuta ese ciclo de forma autónoma y acotada, produce un
informe profesional con evidencia y trazabilidad, y escala a un humano solo
cuando hace falta criterio humano.

## Capacidades

- Descubrimiento del proyecto (read-only) con `ProjectProfile` (framework, rutas, endpoints, formularios, tests existentes, riesgos potenciales).
- Motor de requisitos y de riesgos con trazabilidad completa `Requisito → Riesgo → Test → Ejecución → Evidencia → Hallazgo → Gate de Calidad`.
- Planificación priorizada por riesgo con IDs estables y detección de tests imposibles.
- Generación de tests sin duplicados ni equivalentes.
- Registro de skills declarativo — nuevas skills sin tocar el orquestador.
- Executor determinista con sesión real de navegador (crawling, consola, a11y, API, formularios) acotada por el scope guard y presupuestos.
- Gestión de evidencia con redacción central (nunca persiste secretos).
- Analizador de fallos (taxonomía de 12 tipos), reintento solo de fallos transitorios (máx. 3), detección de tests flaky.
- Hallazgos unificados con severidad, confianza, deduplicación y estados.
- Gate de calidad con 5 estados (`PASS / PASS_WITH_WARNINGS / FAIL / BLOCKED / NEEDS_HUMAN`) y umbral de cobertura configurable por perfil.
- Informes en Markdown / HTML / JSON + borrador de tickets Jira.
- Manifiesto de ejecución reproducible + recuperación ante crash (una ejecución interrumpida nunca parece exitosa).

## Arquitectura

```
Orchestrator (máquina de estados acotada, MAX 48 pasos)
├── Discovery            ├── Failure Analyzer / Retry / Flaky
├── Requirements Engine  ├── Finding Manager (dedup + confianza)
├── Risk Engine          ├── Coverage Engine
├── Planner / Generator  ├── Quality Gate (política por perfil)
├── Skill Registry       ├── Reports (MD/HTML/JSON/Jira)
├── Executor + live      ├── Run Manifest (atómico)
└── Evidence Manager     └── Human Escalation
```

Módulos clave: `core/orchestrator.py`, `core/live_session.py` (sesión real de
Playwright: un ciclo abrir→auditar→cerrar por operación, siempre dentro del
scope y del presupuesto), `core/scope.py` (DENY UNKNOWN), `core/config.py`
(perfiles), `core/redaction.py`.

## Instalación

```bash
git clone <repo>
cd QA_Automation_Agent
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt     # Windows
# .venv/bin/pip install -r requirements.txt       # Linux/macOS
.venv/Scripts/playwright install chromium
```

Requisitos: Python 3.10+ y Chromium vía Playwright.

## CLI

```bash
.venv/Scripts/python main.py discover <objetivo>   # perfil del proyecto (read-only)
.venv/Scripts/python main.py plan <objetivo>       # requisitos + riesgos + plan (sin ejecución)
.venv/Scripts/python main.py run <objetivo>        # ciclo autónomo completo
.venv/Scripts/python main.py report <run-dir>      # resume/re-renderiza una ejecución previa
.venv/Scripts/python main.py validate <run-dir>    # verificación de crash-recovery + gate (exit code)
```

Flags habituales:

| Flag | Significado |
|---|---|
| `--profile safe\|standard\|deep\|ci` | perfil de configuración |
| `--url URL` | origen explícito para el scope |
| `--risk low\|medium\|high` | nivel de riesgo de la ejecución |
| `--browser chromium\|firefox\|webkit` | motor de Playwright |
| `--headed` / `--headless` | visibilidad del navegador |
| `--output DIR` | directorio de informes |
| `--budget max_pages=10,max_requests=20` | overrides de presupuesto |
| `--scope origin=https://host,allow_external=true` | overrides de scope |
| `--config FILE` | JSON extra (ej. `destructive: false`) |
| `--min-coverage 0.0–1.0` | umbral de cobertura de requisitos (0 lo desactiva) |
| `--dry-run` | solo planifica; nunca ejecuta |

Códigos de salida: `0` OK/avisos, `1` gate FAIL o interrumpido,
`2` escalado/error de configuración, `130` interrupción de teclado.

## Ejemplo de ejecución (demo reproducible)

```bash
# servir la demo sintética (acotada, solo localhost)
cd samples/demo_site
../../.venv/Scripts/python server.py --port 8000 --max-requests 200

# auditarla
cd ../..
.venv/Scripts/python main.py run samples/demo_site --profile standard \
    --url http://127.0.0.1:8000 --output reports/demo_run --min-coverage 0.02
```

Salida en `reports/demo_run/`: `audit_report.md`, `audit_report.html`,
`audit_report.json`, `jira_export.md`, `run_manifest.json`, `run_evidence.json`.

Hallazgos esperables en la demo: enlace roto, errores de consola deliberados,
imagen sin `alt`, endpoint 500, JSON malformado, omisiones de scope
(`/admin` bloqueado, POST fuera de allowlist).

## Estructura del informe

Markdown/HTML/JSON incluyen: Resumen Ejecutivo, Perfil del Proyecto, Scope,
Entorno, Riesgos, Requisitos, Cobertura, Tests Planificados/Ejecutados/
Exitosos/Fallidos/Bloqueados/Flaky, Hallazgos (severidad, confianza,
evidencia, reproducción), Reintentos, Escalados, Limitaciones, Gate de
Calidad, Recomendaciones y Manifiesto de Ejecución. `jira_export.md` es un
borrador de ticket por hallazgo.

## Perfiles de configuración

| Perfil | Páginas | Requests | Profundidad | Runtime | Umbral cobertura | Uso |
|---|---|---|---|---|---|---|
| `safe` | 5 | 20 | 1 | 120 s | 10% | primer contacto, smoke |
| `standard` | 25 | 100 | 2 | 300 s | 20% | por defecto |
| `deep` | 100 | 500 | 4 | 1800 s | 30% | auditorías profundas |
| `ci` | standard + headless + 600 s | | | | desactivado | pipelines |

Todos los perfiles comparten la misma base de seguridad: same-origin, sin
uploads, sin escritura en filesystem, sin acciones destructivas, redacción
siempre activa.

## Modelo de seguridad

- **DESCUBRIMIENTO READ-ONLY** — nunca escribe en el objetivo.
- **DENY UNKNOWN** — se rechaza todo origen cruzado salvo permiso explícito; tokens de ruta bloqueados (`/admin`, `/delete`, `/drop`, `/reset`, `/logout`) denegados por defecto.
- **Presupuestos STOP** — al agotarse, la ejecución para; nunca se resetean.
- **Reintentos acotados** — solo fallos transitorios, máx. 3, nunca bugs confirmados ni acciones destructivas.
- **Redacción central** — contraseñas, tokens, cookies y cabeceras de autorización se sustituyen por `[REDACTED]` antes de persistir.
- **Sin telemetría** — nada sale de tu máquina.

## Objetivos soportados

- Proyectos locales (cualquier stack): descubrimiento + planificación (nivel bind).
- Sitios/APIs HTTP(S) de tu propiedad: ciclo completo con sesión real de navegador.
- La demo sintética `samples/demo_site` para pruebas reproducibles.

## Solución de problemas

| Síntoma | Causa / solución |
|---|---|
| `configuration error: ...` | Validación fail-fast. Corrige el perfil/URL/presupuesto indicado. |
| Gate FAIL por cobertura | Baja el umbral con `--min-coverage`, usa `--profile ci`, o revisa el alcance. |
| `Playwright not installed` | Ejecuta `.venv/Scripts/playwright install chromium`. |
| Ejecución INTERRUMPIDA | El manifiesto registra la interrupción; corrige la causa y re-ejecuta. |
| Puerto de demo en uso | Usa otro `--port` para el servidor de la demo. |

## Limitaciones

- Las comprobaciones de accesibilidad son heurísticas parciales y **no** certifican cumplimiento WCAG.
- La cobertura mide el mapeo requisitos→tests, no la cobertura de código del objetivo.
- Las skills con navegador ejecutan sesiones reales solo contra objetivos HTTP(S); en `--dry-run` y proyectos locales la evidencia es de nivel bind (INFO).
- El ejercicio de formularios es defensivo: solo envíos vacíos con el método declarado por el formulario — sin inyección ni fuzzing contra objetivos en vivo.
- Los hallazgos derivados de requisitos INFERIDOS son hipótesis y requieren confirmación humana.
- El crawler sigue enlaces same-origin; SPAs con JS pesado pueden requerir presupuestos mayores.
- Sin integraciones cloud/CI incluidas; todo se ejecuta localmente.

## Posicionamiento comercial

Para equipos que necesitan cobertura de QA repetible sin enviar datos fuera
de su entorno: auditorías previas a release, regresión de humo en CI,
onboarding de proyectos heredados, y pre-screening en due diligence de
software. El agente amplifica al ingeniero de QA — no lo reemplaza.
