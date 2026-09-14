# QA AUTOMATION AGENT — SPECIFICACIÓN FASE 1/2

## Problema

El repositorio actual contiene un esqueleto funcional de orquestador QA, pero le faltan las capacidades empresariales requeridas para ser un agente autónomo, local, seguro y comercialmente defendible. Falta trazabilidad end-to-end, modelos unificados completos, motor de requisitos, motor de riesgos, generador de tests, budget centralizado, gobernador de recursos, análisis de flaky, deduplicación de findings, cobertura, configuración estructurada, CLI completo, y recuperación ante fallos.

## Usuarios

- **QA Engineers autónomos**: necesitan ejecutar `qa-agent run <target>` y obtener un reporte ejecutivo con calidad gate.
- **Equipos Enterprise**: necesitan auditorías locales sin fuga de datos, trazabilidad requisito→riesgo→test→finding, y perfiles de configuración (safe/standard/deep/ci).
- **Desarrolladores locales**: necesitan `discover` y `plan` para entender el scope antes de ejecutar nada destructivo.

## Objetivos

1. Transformar el repositorio en un QA Automation Agent completo con el ciclo: DISCOVERY → REQUIREMENTS → RISK → PLAN → GENERATE → EXECUTE → EVIDENCE → FAILURE ANALYSIS → RETRY → FINDINGS → QUALITY GATE → REPORT → ESCALATION.
2. Reutilizar los 5 motores existentes (crawler, form_tester, a11y_auditor, api_auditor, report_builder) sin rewrite innecesario; solo blindar y adaptar sus contratos.
3. Implementar 16+ modelos centrales tipados y validados con trazabilidad bidireccional.
4. Blindar seguridad por defecto: READ-ONLY, DENY UNKNOWN, NO SECRET LOGGING, NO DESTRUCTIVE ACTIONS.
5. Preparar el repositorio para FASE 2 (validación adversarial y testing integral).

## No-objetivos

- NO ejecutar pytest completo en esta fase.
- NO agregar integraciones cloud.
- NO agregar LLM con capacidad ejecutiva directa.
- NO reemplazar Playwright async / Pytest / Jinja2 como runtime base.
- NO afirmar cumplimiento WCAG completo (solo heurísticas parciales declaradas como tales).

---

## Requisitos Funcionales

### FR-01 Modelos unificados y validados
Todos los módulos comparten 16+ modelos centrales en `core/models.py` con tipado Pydantic 2.x y validación. Incluye: Project, ProjectScope, ProjectProfile, Requirement, Risk, TestCase, TestStep, TestResult, Finding, Evidence, ExecutionRun, ExecutionConfig, Budget, RetryDecision, Escalation, QualityGate, RunManifest. Cada modelo tiene IDs estables para trazabilidad.

### FR-02 Trazabilidad end-to-end
Se puede seguir la cadena: Requirement → Risk → TestCase → Execution → Evidence → Finding → QualityGate. Expone métodos para: (a) qué requisito originó un test, (b) qué test produjo un finding, (c) qué evidencia respalda un finding, (d) qué requisitos no tienen cobertura.

### FR-03 Project Discovery READ-ONLY
`core/discovery.py` extendido. Detecta framework, frontend, backend, APIs, routes, forms, package manager, dependencies, test infra, configuration, documentation, authentication requirements, entry points, riesgos potenciales. Genera `ProjectProfile`. NUNCA modifica el target.

### FR-04 Requirements Engine
`core/requirements_engine.py` (nuevo). Convierte README, documentación, rutas, APIs, configuración, HTML, tests existentes en requisitos verificables. Cada requisito clasificado como: explicit | inferred | unknown. Nunca presenta inferencia como confirmado.

### FR-05 Risk Engine
`core/risk_engine.py` (nuevo). Evalúa impact, likelihood, complexity, exposure, authentication, data sensitivity, business criticality. Clasifica CRITICAL / HIGH / MEDIUM / LOW. Prioriza riesgos altos.

### FR-06 Test Planner
`core/planner.py` extendido. Planes estructurados con test_id, requirement_id, risk, skill, preconditions, actions, expected_result, cleanup, priority, budget. El planner NO ejecuta.

### FR-07 Test Generator
`core/test_generator.py` (nuevo). Genera tests a partir del plan: evita duplicados, evita tests equivalentes, detecta tests imposibles, respeta precondiciones, mantiene IDs estables.

### FR-08 Skill Registry central
`core/skills_registry.py` extendido. Cada skill declara: name, version, purpose, inputs, outputs, required_tools, risk, timeout, resource_budget, supported_targets. Registra skills existentes. Arquitectura permite agregar futuras skills sin modificar orchestrator.

### FR-09 Deterministic Executor
Separación explícita: PLAN → ACTION → EXECUTION → OBSERVATION → RESULT. El executor solo ejecuta acciones autorizadas. No permite acciones destructivas por defecto.

### FR-10 Scope Guard DENY UNKNOWN
Límites centrales para: dominios, URLs, endpoints, métodos, profundidad, requests, concurrencia, uploads, filesystem, runtime. Regla por defecto DENY UNKNOWN. Nunca asume URL externa autorizada.

### FR-11 Test Budget
Límites: max_tests, max_requests, max_pages, max_depth, max_runtime, max_retries, max_concurrency, max_artifacts, max_response_size. Cuando se alcanza límite → STOP, no resetear automáticamente.

### FR-12 Resource Governor
Controla: memoria, browser contexts, procesos, archivos temporales, response size, screenshots, runtime. Evita crecimiento ilimitado.

### FR-13 Crawler Hardening
Blinda contra: loops, URLs duplicadas, fragments, redirect loops, infinite pagination, external domains, huge pages. Mantiene límites depth/URLs/requests/concurrency/timeout. Registra por qué URL fue omitida.

### FR-14 Form Testing bounded
Pruebas sintéticas bounded: empty, whitespace, boundary lengths, Unicode, malformed values, unexpected types, special characters. Security payloads SÓLO sintéticos, harmless, bounded, no destructivos.

### FR-15 API Auditor
Detecta: 4xx, 5xx, malformed JSON, invalid content type, schema anomalies, slow responses, timeout, redirects, missing important headers. NO registra secrets.

### FR-16 Accessibility Auditor
Audita como mínimo: alt, labels, headings, ARIA, buttons, form controls, duplicate IDs, basic semantic structure. NO declara cumplimiento WCAG completo mediante heurísticas parciales.

### FR-17 Session / Auth Management
Soporte seguro para: anonymous, authenticated, expired_session, invalid_credentials. NUNCA escribe passwords, cookies, tokens, authorization headers en logs o reports.

### FR-18 Failure Analyzer taxonomía completa
Taxonomía: PRODUCT_BUG, TEST_BUG, ENVIRONMENT_FAILURE, NETWORK_FAILURE, TIMEOUT, DEPENDENCY_FAILURE, AUTH_FAILURE, CONFIGURATION_FAILURE, DATA_PROBLEM, BROWSER_FAILURE, INFRASTRUCTURE_FAILURE, UNKNOWN. Analiza expected/actual/stack trace/console/network/timing/environment.

### FR-19 Retry Controller
Retry SÓLO ante problemas plausiblemente transitorios: timeout, transient network failure, browser crash, infrastructure failure, probable flaky behavior. No retry automático ante confirmed functional bugs, scope violations, destructive situations. Máximo 3 retries por problema.

### FR-20 Flaky Test Detection
Distinción: PASS, FAIL, FLAKY, BLOCKED, ERROR. Resultado inconsistente NO se convierte automáticamente en bug confirmado.

### FR-21 Finding Manager unificado
Finding con: finding_id, category, severity, confidence, title, description, location, evidence, reproduction, expected, actual, source_skill, status, recommendation. Categorías: functional, ui, api, accessibility, performance, security, data_integrity, configuration, infrastructure. Estados: open, confirmed, false_positive, resolved, needs_human.

### FR-22 Finding Deduplication
Fingerprints basados en: category, location, normalized title, error signature, route/endpoint, stack signature. Evita reportar mismo problema repetidamente.

### FR-23 Confidence scoring
LOW / MEDIUM / HIGH basado en: reproducibility, evidence quality, deterministic behavior, source skill, failure classification.

### FR-24 Evidence Manager
Gestiona: screenshots, DOM snapshots, console errors, network metadata, response metadata, timings, logs, reproduction steps. Cada evidencia asociada a run_id + test_id + finding_id. Evita información sensible.

### FR-25 Sensitive Data Redaction central
UNA capa central aplicada ANTES de persistir: passwords, API keys, tokens, authorization, cookies, secrets, connection strings, credentials. Aplica en: logs, HTML, Markdown, JSON, Jira, evidence metadata. NO depende de cada skill individual.

### FR-26 Run Manifest completo
Cada ejecución registra: run_id, agent_version, timestamp, python_version, OS, browser, project_fingerprint, scope, configuration, budget, tests_planned, tests_executed, findings, artifacts, quality_gate. NUNCA secrets.

### FR-27 Reproducibility
Suficiente información para explicar: qué se ejecutó, por qué, contra qué target, con qué configuración, con qué presupuesto, qué resultado produjo.

### FR-28 Idempotency
Evita: findings duplicados, artifacts acumulativos incorrectos, resultados dependientes de estado previo, IDs innecesariamente aleatorios. Dos runs equivalentes producen resultados razonablemente comparables.

### FR-29 Autonomous State Machine
Estados explícitos: DISCOVER, ANALYZE, PLAN, EXECUTE, ANALYZE_FAILURE, RETRY, CONTINUE, STOP, ESCALATE, REPORT. No transiciones infinitas. Límite global de pasos.

### FR-30 Human Escalation
Escalar cuando: scope ambiguo, faltan credenciales, acción potencialmente destructiva requerida, entorno incierto, evidencia insuficiente, fallo no reproducible, authentication challenge, infraestructura inaccesible, incertidumbre crítica. Agente explica WHY + WHAT WAS ATTEMPTED + WHAT EVIDENCE EXISTS + WHAT HUMAN INPUT IS REQUIRED.

### FR-31 Quality Gate
Resultado: PASS, PASS_WITH_WARNINGS, FAIL, BLOCKED, NEEDS_HUMAN. Considera: critical findings, high findings, unresolved findings, blocked tests, coverage, confidence, flakiness, scope limitations.

### FR-32 Coverage Engine
Mide: requirements coverage, test coverage, risk coverage, execution coverage. Estados: covered, partially_covered, not_covered, blocked, unknown. NO code coverage del target.

### FR-33 Report Engine completo
Genera HTML, Markdown, JSON. Incluye: Executive Summary, Project Profile, Scope, Environment, Risk Summary, Requirements, Coverage, Tests Planned, Tests Executed, Passed, Failed, Blocked, Flaky, Findings, Evidence, Retries, Escalations, Limitations, Quality Gate, Recommendations, Run Manifest. Mantiene Jira exporter.

### FR-34 CLI profesional
Subcomandos: `qa-agent discover <target>`, `qa-agent plan <target>`, `qa-agent run <target>`, `qa-agent report <run>`, `qa-agent validate <run>`. Flags cuando apropiado: --scope, --budget, --browser, --headed, --headless, --output, --risk, --dry-run, --config.

### FR-35 Configuration Profiles
Perfiles: safe, standard, deep, ci. Todos respetan mismos límites de seguridad.

### FR-36 Config Validation fail-fast
Falla rápido ante: límites negativos, URLs inválidas, budgets imposibles, configuración corrupta, combinaciones inseguras.

### FR-37 Crash Recovery
Maneja: worker crash, browser crash, subprocess crash, timeout, cancellation, KeyboardInterrupt, artifact corruption. Ejecución interrumpida NUNCA debe parecer exitosa.

### FR-38 Atomic Artifact Writes
Para reports/manifests importantes: temporary file → flush → validate → atomic rename. Evita archivos parcialmente escritos que parezcan válidos.

### FR-39 Structured Logging
Separación DEBUG/INFO/WARNING/ERROR/CRITICAL. Agrega run_id. NUNCA registrar secrets.

### FR-40 Observability
Agente puede explicar: qué está haciendo, por qué, qué presupuesto queda, qué test ejecutó, por qué hizo retry, por qué omitió algo, por qué escaló.

### FR-41 Security Model by default
READ-ONLY DISCOVERY, BOUNDED EXECUTION, DENY UNKNOWN, NO DESTRUCTIVE ACTIONS, NO SECRET LOGGING, NO UNCONTROLLED FUZZING, NO UNCONTROLLED CRAWLING. NUNCA: borrar datos, modificar producción, DoS, explotar terceros, ejecutar comandos arbitrarios contra targets, enviar datos del target a servicios externos.

### FR-42 LLM Boundary (si aplica en futuro)
LLM sólamente PROPOSE. NUNCA ejecuta directamente shell/filesystem/browser/network/destructive operations. Flujo: PROPOSAL → VALIDATION → AUTHORIZED ACTION.

### FR-43 Memory separation
AGENTS.md = memoria estática (arquitectura, reglas, convenciones, seguridad, comandos, debugging). Runtime artifacts = runs, findings, evidence, manifests. No mezclar.

### FR-44 Synthetic Demo target
Target local seguro con problemas deliberados: broken link, accessibility issue, invalid form behavior, API error, console error, slow response, findings relacionados. Auditado reproduciblemente.

### FR-45 Agent Self-Test architecture
Tests preparados para: models, scope, budget, orchestrator, state machine, retries, redaction, findings, evidence, reporting, recovery. NO ejecutar suite completa aún.

### FR-46 Documentation actualizado
README actualizado con: propósito, arquitectura, instalación, CLI, configuración, safety model, limitations, example run, report structure, supported targets, troubleshooting, commercial positioning. NO afirmar que reemplaza completamente a QA humano.

### FR-47 Dependency Hygiene
Revisar requirements: dependencias duplicadas, dependencias sin uso, compatibilidad Python, Playwright, Pytest. NO agregar librerías innecesarias.

### FR-48 Static Hardening
Después de implementar TODO: buscar broken imports, circular imports, dead code, duplicate logic, stubs, critical TODOs, fake implementations, unsafe defaults, secret leakage, unbounded loops, unbounded concurrency, incorrect async usage, inconsistent models. Corregir lo necesario.

### FR-49 Final Pre-Test Review
Verificar pipeline completo: CLI → Orchestrator → Discovery → Requirements → Risk → Planner → Generator → Registry → Executor → Skills → Evidence → Failure Analyzer → Findings → Quality Gate → Reports. Más Scope, Budget, Redaction, Logging, Recovery, Configuration, Escalation.

---

## Requisitos No Funcionales

### NFR-01 Python 3.10+, Pydantic 2.x, Playwright async, Pytest, Jinja2
Runtime ya establecido en requirements.txt. No introducir framework alternativo.

### NFR-02 Zero cloud data privacy
Toda evidencia, logs, screenshots, reports y manifests quedan estrictamente locales. Ningún upload automático.

### NFR-03 Build-first, test-last (esta fase)
Esta fase es AUDIT + DESIGN + BUILD + HARDENING. NO pytest completo. NO ciclos test/fix. Sólo verificaciones sintácticas mínimas.

### NFR-04 Anti-bucle
Ningún módulo se modifica repetidamente en ciclos test-fix. Cada archivo recibe su implementación final en una pasada.

### NFR-05 Determinismo
IDs estables donde sea posible; fingerprints reproducibles; ordenamiento determinista en colecciones expuestas.

### NFR-06 Tracing y seguridad
Ningún log, finding ni report contiene secrets. Redaction centralizada se ejecuta en el write path.

---

## Restricciones

1. **NO rewrite innecesario.** Los motores existentes (crawler.py, form_tester.py, a11y_auditor.py, api_auditor.py, report_builder.py) se adaptan, no se reescriben.
2. **NO librerías nuevas.** requirements.txt ya contiene pydantic, playwright, pytest, pytest-asyncio, selectolax, jinja2, httpx. Se usan esas. Si faltara una función stdlib se prefiere.
3. **NO pytest completo en esta fase.** Queda para Prompt 2.
4. **NO archivos .md documentales nuevos a menos que el usuario lo pida.** (Excepto los artefactos spec/tasks/review de TRAE-spec-mode.)
5. **Límites por defecto conservadores.** Scope same-origin; budgets low; NO destructive actions por defecto.

## Dependencias

- runtime: pydantic>=2, playwright>=1.40, pytest>=8, pytest-asyncio, selectolax, jinja2>=3.1, httpx>=0.27
- filesystem: local-only evidence dirs, .gitignore cubre .env, .venv, *.log, screenshots, reports/*.html, reports/tmp, reports/final
- skills: 4 skills folder-shaped existentes más registry que los declara

## Suposiciones

1. El target actual es un proyecto Python local y/o una URL HTTP con Playwright disponible.
2. No hay credenciales reales en el repositorio de tests.
3. La versión de Python del entorno es >= 3.10.
4. Las skills futuras seguirán el contrato SkillContract + folder-shaped con SKILL.md.

## Preguntas abiertas

- Ninguna material. El prompt 53 puntos define el scope completamente. Si algo quedara ambiguo se resuelve por la regla de seguridad más restrictiva.

---

## Criterios de Aceptación

### AC-01 (rule) Modelos unificados presentes y validables
`core/models.py` exporta con Pydantic las clases: Project, ProjectScope, ProjectProfile, Requirement, RequirementClassification, Risk, RiskSeverity, TestCase, TestStep, TestResult, TestStatus, Finding, FindingCategory, FindingSeverity, FindingStatus, Confidence, Evidence, ExecutionRun, ExecutionConfig, BudgetConfig, RetryDecision, Escalation, QualityGateResult, QualityGateStatus, RunManifest. Cada una tiene model_validate que pasa con datos coherentes y falla con datos inválidos.

### AC-02 (rule) Trazabilidad bidireccional
Existen funciones/métodos que dado un finding_id retornan test_id, requirement_id y evidence; dado requirement_id retornan tests y coverage state.

### AC-03 (rule) Scope DENY UNKNOWN por defecto
`Scope.is_allowed` retorna False para URLs de origin diferente, métodos no listados, endpoints no declarados, y paths bloqueados. `Scope.assert_allowed` lanza ScopeViolationError.

### AC-04 (rule) Budget STOP sin auto-reset
`Budget.consume_*` retorna False al agotar cualquier límite; `Budget.is_exhausted()` persiste True hasta nuevo Budget.

### AC-05 (rule) Redaction centralizada es el único write path
EvidenceManager, ReportBuilder, RunManifest, StructuredLogger todos usan la misma instancia/clase de redaction. En ningún módulo se escriben strings sensibles sin pasar por redaction.

### AC-06 (rule) Skill registry extensible sin modificar orchestrator
Agregar un `SkillContract` nuevo via `registry.register(...)` es suficiente; Orchestrator y Executor NO requieren edición.

### AC-07 (rule) State machine con límite global de pasos
Orchestrator expone un contador `max_steps` (default 1000). Al alcanzarlo transiciona a STOP. Ciclos: ninguno alcanza más de max_steps.

### AC-08 (rule) CLI con 5 subcomandos y flags
`main.py` parsea discover / plan / run / report / validate. Flags --scope --budget --browser --headed --headless --output --risk --dry-run --config presentes o documentados como N/A en el subcomando correspondiente.

### AC-09 (rule) 4 configuration profiles validados
Profiles safe / standard / deep / ci se cargan y cada uno produce budgets y scope coherentes. Todos comparten: no destructive, same-origin por defecto, max_retries ≤ 3.

### AC-10 (rule) Atomic artifact writes
`atomic_write(path, content_bytes)` implementa tmp → flush → fsync → rename. Run manifest y JSON report usan esta función.

### AC-11 (rule) Crash recovery marca interrumpido como no-exitoso
Si KeyboardInterrupt / Timeout / Exception corta Orchestrator.run(), el RunManifest guardado tiene quality_gate.status = BLOCKED y notes = ["interrupted"].

### AC-12 (rule) Finding deduplication fingerprint
Dos Finding con misma category, location (normalizada), normalized title (lower/strip) y error signature se marcan como duplicados; solo uno persiste en findings finales.

### AC-13 (rule) Quality Gate 5 estados
QualityGateResult.status ∈ {PASS, PASS_WITH_WARNINGS, FAIL, BLOCKED, NEEDS_HUMAN}. Evaluación incluye coverage_score ≥ 0 + high/critical findings count + flaky ratio + blocked ratio.

### AC-14 (rule) Synthetic demo target reproduce issues
Un archivo HTML (demo target) contiene: 1 broken link href, 1 img sin alt, 1 form sin label, 1 endpoint /api/slow 2s, 1 console.error onload. Al auditarlo el pipeline produce al menos 5 findings de categorías diferentes.

### AC-15 (rule) .gitignore cubre artifacts sensibles
Incluye: .venv, env, __pycache__, .env*, *.log, trace.zip, *.png/*.jpg/*.jpeg, evidence/, reports/*.html reports/*.json reports/tmp reports/final, .pytest_cache, temp/, jira_export.md, run_manifest.json, run_evidence.json.

### AC-16 (rubric) Arquitectura cohesionada, baja fricción intermodular
Escala 0..2:
- 2: imports acíclicos, cada módulo ~una responsabilidad, contratos (Action/Result/Model) claros, menos de 5 "core.X import" circulares detectables estáticamente.
- 1: funcional pero con 1-2 dependencias cíclicas o un módulo >800 líneas.
- 0: acoplamiento fuerte, imports circulares múltiples, módulos monolíticos.

### AC-17 (rubric) Seguridad por defecto efectiva
Escala 0..2:
- 2: DENY UNKNOWN, NO destructive default, cada write path pasa por redaction, logger NO emite secrets ni tokens en modo DEBUG.
- 1: 2 de 3 aspectos cumplidos.
- 0: hay write paths sin redaction o destructive actions por defecto.

### AC-18 (rubric) Report completeness
Escala 0..2:
- 2: Markdown + HTML + JSON contienen todas las secciones listadas en FR-33. Templates acceden a campos correctos del modelo Finding (no .kind/.url/.detail sino .category/.location/.description).
- 1: ≥ 80% secciones presentes; 1-2 templates tienen campos erróneos.
- 0: ≤50% secciones; templates rotos.
