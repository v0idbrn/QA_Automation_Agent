# QA AUTOMATION AGENT — TAREAS DE IMPLEMENTACIÓN

Mapa de criterios de aceptación (AC) a tareas. Procesar en orden estricto (dependencias).

---

## Task 1: Modelos unificados en core/models.py

**Status**: pending
**Priority**: high
**Parent ACs**: AC-01, AC-02

### Descripción
Sustituir y extender `core/models.py` actual. Mantener `Finding`, `Severity`, `RedactionPolicy` existentes pero normalizar campos. Agregar 16+ modelos nuevos con Pydantic BaseModel + tipado estricto + validación.

### Archivos impactados
- Modificar: `core/models.py`
- Modificar: `core/manifest.py` (re-export desde models)

### Test Requirements (TRs)

#### TR-1.1 (rule) Todos los 16+ modelos son instanciables
`from core.models import <N>` para: Project, ProjectScope, ProjectProfile, Requirement, Risk, TestCase, TestStep, TestResult, Finding, Evidence, ExecutionRun, ExecutionConfig, BudgetConfig, RetryDecision, Escalation, QualityGateResult, RunManifest, Confidence, RequirementClassification, RiskSeverity, FindingCategory, FindingSeverity, FindingStatus, QualityGateStatus, TestStatus. Todo importa sin error.

#### TR-1.2 (rule) Validación Pydantic falla con datos inválidos
`QualityGateResult(passed=5)` o `Severity("nope")` → ValidationError o ValueError.

#### TR-1.3 (rule) IDs de trazabilidad enlazan modelos
`TestCase.requirement_id`, `Finding.test_id`, `Finding.evidence_ids`, `Evidence.test_id`, `Evidence.run_id` son campos declarados y accesibles.

### Evidencia de finalización
- Import de todos los modelos en un solo `python -c` sin excepciones.
- Snippet de validación negativa que atrapa ValidationError.

---

## Task 2: Scope + Budget + Scope Guard + Resource Governor

**Status**: pending
**Priority**: high
**Parent ACs**: AC-03, AC-04, FR-10, FR-11, FR-12

### Descripción
Extender `core/scope.py` con: ScopeGuard DENY UNKNOWN (endpoints, HTTP methods, filesystem, uploads), BudgetConfig completo (max_tests, max_retries, max_concurrency, max_artifacts, max_response_size), ResourceGovernor (memoria aproximada, browser contexts, temp files, response size caps, screenshot caps, runtime). Preservar Budget existente pero migrar campos a BudgetConfig.

### Archivos impactados
- Modificar: `core/scope.py` (Scope, Budget, agregar ScopeGuard, ResourceGovernor)
- Modificar imports en otros módulos si cambian nombres (mantener backward compat aliases).

### Test Requirements

#### TR-2.1 (rule) DENY UNKNOWN por defecto en origen distinto
`Scope(allowed_origin="https://a.test").is_allowed("https://b.test/x")` → False.
`Scope(allowed_origin="https://a.test").assert_allowed("https://b.test")` → ScopeViolationError.

#### TR-2.2 (rule) Budget STOP sin auto-reset
`Budget` con `max_pages=1` → `consume_page()`×2 retorna [True, False]; `is_exhausted()`=True y permanece True.

#### TR-2.3 (rule) ResourceGovernor limita response size
`ResourceGovernor(max_response_bytes=100).consume_response(200)` → False / marca exhausted.

### Evidencia de finalización
- Snippet `python -c` para cada regla.
- Archivo modificado sin imports rotos.

---

## Task 3: Project Discovery (READ-ONLY) extendido

**Status**: pending
**Priority**: high
**Parent ACs**: FR-03, AC-02

### Descripción
Extender `core/discovery.py`. Mantener `ProjectProfile` pero migrarlo a heredar del modelo Pydantic en models.py (o alias). Añadir detecciones: forms en HTML leídos, configuración (.env.example, setup.cfg, pyproject sections), dependencies en package.json/requirements.txt con nombres, frontend vs backend heuristics, riesgos potenciales (admin/, /login, auth markers). NUNCA escribe archivos.

### Archivos impactados
- Modificar: `core/discovery.py`

### Test Requirements

#### TR-3.1 (rule) discover_project no escribe archivos
Llamar `discover_project` sobre tmp_path con README.md dummy; comprobar que ningún archivo nuevo fue creado.

#### TR-3.2 (rule) ProjectProfile resultante tiene campos extendidos
`profile.forms_dected`, `profile.config_files`, `profile.dependencies`, `profile.potential_risks` existen como listas (vacías permitidas).

### Evidencia
- Ejecución sintáctica sobre tmp_path sin side effects.

---

## Task 4: Requirements Engine + Spec Analyzer fusionados

**Status**: pending
**Priority**: high
**Parent ACs**: FR-04, AC-02

### Descripción
Crear `core/requirements_engine.py`. Reutiliza `core/spec_analyzer.py` (OBSERVED/INFERRED/UNKNOWN) pero convierte statements en `Requirement` del modelo unificado. Extrae requisitos también desde: routes detectadas, api_endpoints, forms encontrados, test files existentes. Clasifica explicit|inferred|unknown.

### Archivos impactados
- Crear: `core/requirements_engine.py`
- Modificar: `core/spec_analyzer.py` (pequeños ajustes de integración, NO rewrite)

### Test Requirements

#### TR-4.1 (rule) Requirement classification ∈ {explicit inferred unknown}
Cada `Requirement.classification` es uno de los 3. Explícito solo si proviene de línea concreta de README/OpenAPI.

#### TR-4.2 (rule) Inferencias NUNCA tienen classification=explicit
Spec statements con SpecConfidence.INFERRED → Requirement.classification="inferred".

### Evidencia
- Import `core.requirements_engine.extract_requirements(profile, spec)` retorna list[Requirement] no vacío sobre perfil con README+routes.

---

## Task 5: Risk Engine

**Status**: pending
**Priority**: high
**Parent ACs**: FR-05, AC-02

### Descripción
Crear `core/risk_engine.py`. Por cada Requirement evalúa impact × likelihood × complexity × exposure + authentication + data_sensitivity + business_criticality (cada uno 1..5). Promedio ponderado → RiskSeverity CRITICAL/HIGH/MEDIUM/LOW. Cada Risk enlaza `requirement_id`.

### Archivos impactados
- Crear: `core/risk_engine.py`

### Test Requirements

#### TR-5.1 (rule) RiskSeverity 4 niveles definidos y comparables
`CRITICAL > HIGH > MEDIUM > LOW` en orden de severidad.

#### TR-5.2 (rule) Requirement con auth_required + business_critical → CRITICAL o HIGH
Riesgo no baja a LOW/MEDIUM si ambos flags están activos.

### Evidencia
- Ejemplo sintáctico de evaluación con 2+ requirements.

---

## Task 6: Test Planner extendido + Test Generator nuevo

**Status**: pending
**Priority**: high
**Parent ACs**: FR-06, FR-07, AC-02

### Descripción
Extender `core/planner.py`: PlanItem → heredar campos de TestCase (test_id, requirement_id, risk, skill, preconditions, actions, expected_result, cleanup, priority, budget). Crear `core/test_generator.py`: desde TestPlan produce list[TestCase] SIN duplicados (por fingerprint de requirement+skill+action hash), detecta tests imposibles (preconditions no cumplibles), mantiene IDs estables (hash determinista).

### Archivos impactados
- Modificar: `core/planner.py`
- Crear: `core/test_generator.py`

### Test Requirements

#### TR-6.1 (rule) TestGenerator NO duplica tests equivalentes
Dos PlanItems con mismo requirement_id + skill + misma action → 1 solo TestCase generado.

#### TR-6.2 (rule) TestCase.test_id es estable
Mismo input → mismo test_id (no uuid random; usar sha1 hex truncado de inputs).

### Evidencia
- Generar TestCases a partir de un TestPlan pequeño. Conteo == PlanItems únicos.

---

## Task 7: Skill Registry + Action/Result contracts extendidos

**Status**: pending
**Priority**: high
**Parent ACs**: FR-08, FR-09, AC-06

### Descripción
Extender `core/skills_registry.py` SkillContract: añadir version, purpose, inputs, outputs, required_tools, risk, timeout, resource_budget, supported_targets. Extender `core/actions.py` Action con test_id, timeout, resource_budget. Extender Result con test_id, execution_time_ms, evidence_ids, flaky_indicator. Mantener handlers existentes adaptados a nuevos campos.

### Archivos impactados
- Modificar: `core/skills_registry.py`
- Modificar: `core/actions.py`

### Test Requirements

#### TR-7.1 (rule) Registry admite nuevas skills sin tocar Orchestrator
Llamar `SkillRegistry().register(SkillContract(name="x", handler=lambda a,c: Result(ok=True), ...))` y `registry.get("x")` no None. Orchestrator sin editar.

#### TR-7.2 (rule) Action/Result con nuevos campos default a cero/vacío
Instanciar Action/Result sin argumentos nuevos → valores default razonables (0, [], None compatible).

### Evidencia
- Registro de 1 skill dummy exitoso.

---

## Task 8: Deterministic Executor + ScopeGuard enforcement

**Status**: pending
**Priority**: high
**Parent ACs**: FR-09, FR-10, AC-03

### Descripción
Mantener Executor en `core/orchestrator.py`. Integrar: antes de cada execute() → ScopeGuard.assert_allowed + ResourceGovernor.pre_check. Si destructive=True y risk_level!="explicit_override" → bloquear. Ejecución sólo de acciones autorizadas.

### Archivos impactados
- Modificar: `core/orchestrator.py` (Executor)

### Test Requirements

#### TR-8.1 (rule) Destructive Action bloqueada por defecto
`Action(destructive=True, ...)` en executor default → Result(ok=False, skipped=True, error="destructive blocked").

#### TR-8.2 (rule) Scope violation en URL → Result fallido y no ejecuta handler real
Con scope https://a.test; action params con target https://evil → error scope antes de llamar handler.

### Evidencia
- Snippet con Executor + 2 acciones (normal, destructive) → resultados esperados.

---

## Task 9: Failure Analyzer taxonomía completa + Retry Controller + Flaky Detector

**Status**: pending
**Priority**: high
**Parent ACs**: FR-18, FR-19, FR-20

### Descripción
Extender `core/failure_analyzer.py`: ampliar FailureType a 12 valores (PRODUCT_BUG, TEST_BUG, ENVIRONMENT_FAILURE, NETWORK_FAILURE, TIMEOUT, DEPENDENCY_FAILURE, AUTH_FAILURE, CONFIGURATION_FAILURE, DATA_PROBLEM, BROWSER_FAILURE, INFRASTRUCTURE_FAILURE, UNKNOWN). Separar `RetryController` (max 3 retries por signature, sólo transient). Separar `FlakyDetector` (registra N runs por test_id y clasifica PASS/FAIL/FLAKY/BLOCKED/ERROR). Mantener mapeo con LegacyFailureAnalyzer.

### Archivos impactados
- Modificar: `core/failure_analyzer.py` (agregar RetryController, FlakyDetector)

### Test Requirements

#### TR-9.1 (rule) RetryController.limit retorna False a 4to intento con misma signature
3 veces True; 4ta False. Contador persiste.

#### TR-9.2 (rule) PRODUCT_BUG / AUTH_FAILURE / CONFIGURATION_FAILURE son NO-retryables
`should_retry(PRODUCT_BUG)` → False.

#### TR-9.3 (rule) FlakyDetector marca FLAKY si 2 runs [PASS, FAIL] mismo test_id
Classification = FLAKY; NO auto-promover a confirmed bug.

### Evidencia
- Instancias de cada clase con secuencias de entradas.

---

## Task 10: Finding Manager + Deduplication + Confidence scoring + Evidence Manager upgrade

**Status**: pending
**Priority**: high
**Parent ACs**: FR-21, FR-22, FR-23, FR-24, AC-12

### Descripción
Extender Finding en models.py (Task 1) con todos los campos (finding_id, category, severity, confidence enum, title, description, location, evidence, reproduction, expected, actual, source_skill, status enum, recommendation). Implementar `FindingDeduplicator` en `core/finding_manager.py` (fingerprint: category + location_normalized + normalized_title + error_signature + route). Implementar `ConfidenceScorer` con 3 niveles LOW/MEDIUM/HIGH. Extender `core/evidence.py` EvidenceManager: cada EvidenceEntry se asocia a run_id, test_id, finding_id; centraliza redaction call antes de store/promote.

### Archivos impactados
- Crear: `core/finding_manager.py`
- Modificar: `core/evidence.py`
- Ya cubierto en Task 1: `core/models.py` campos Finding extendidos.

### Test Requirements

#### TR-10.1 (rule) Deduplicador reduce 2 findings idénticos a 1
Mismo fingerprint → lista final len=1.

#### TR-10.2 (rule) Confidence LOW si evidencia vacía + categoría heurística (a11y parcial)
`ConfidenceScorer().score(finding_sin_evidence) = LOW`.

#### TR-10.3 (rule) EvidenceEntry requiere run_id y test_id (no-None) al almacenar
`store_temporary` sin run_id en metadata → warning o default "unknown" pero con marca de auditoría.

### Evidencia
- Deduplicación sintáctica de 3 findings (2 dup + 1 único) → lista de 2.

---

## Task 11: Sensitive Data Redaction centralizada

**Status**: pending
**Priority**: high
**Parent ACs**: FR-25, AC-05, AC-17

### Descripción
Consolidar `core/security.py` + `RedactionPolicy` existente en models.py en una sola fachada: `core/redaction.py` (único write path). Ampliar patterns: Bearer, Basic, JWT regex, connection strings postgres://user:pass@, mongodb+srv://..., password=, token=, api_key=, secret=, Set-Cookie, Cookie, Authorization. Función `redact(obj)` recursiva sobre str/dict/list/tuple. Logger structured, EvidenceManager, ReportBuilder, RunManifest todos importan esta fachada.

### Archivos impactados
- Crear: `core/redaction.py`
- Modificar: `core/security.py` (re-exportar desde redaction; mantener backward compat)
- Modificar: `core/models.py` (RedactionPolicy delega a redaction.SensitiveRedactor)
- Modificar imports en 4-6 módulos que usaban `core.security.redact_*`

### Test Requirements

#### TR-11.1 (rule) Bearer token regex se redacta en JSON string
`"Authorization: Bearer abc.def.ghi"` → `"Authorization: [REDACTED]"`.

#### TR-11.2 (rule) Connection string con password redactado
`postgres://admin:s3cr3t@db:5432/x` → `postgres://admin:[REDACTED]@db:5432/x`.

#### TR-11.3 (rule) Todos los módulos usan la misma fachada
Grep por `from core.security` y `from core.models import RedactionPolicy`: ambos re-exportan la misma implementación subyacente.

### Evidencia
- 2 snippets de redaction + grep de imports.

---

## Task 12: Run Manifest completo + Atomic Artifact Writes

**Status**: pending
**Priority**: high
**Parent ACs**: FR-26, FR-27, FR-28, FR-38, AC-10

### Descripción
Extender RunManifest en models.py (Task 1) con los 15+ campos. Crear `core/atomic_write.py` con `atomic_write(path: Path, data: bytes | str)`. EvidenceManager.finalize() usa atomic_write para manifest y JSON reports. Reporte JSON usa atomic_write.

### Archivos impactados
- Crear: `core/atomic_write.py`
- Modificar: `core/evidence.py` (finalize)
- Modificar: `core/orchestrator.py` (_write_reports)

### Test Requirements

#### TR-12.1 (rule) atomic_write no deja archivo medio escrito en fallo de escritura a mitad
Simular fallo → archivo final no se crea (archivo tmp sí se borra).

#### TR-12.2 (rule) RunManifest campos mínimos presentes sin secrets
`run_id, agent_version, timestamp, python_version, OS, browser, project_fingerprint, scope, configuration, budget, tests_planned, tests_executed, findings, artifacts, quality_gate`. configuration y budget pasan por redaction.

### Evidencia
- atomic_write(tmp_path, "x") exitoso; verificar tamaño==1 byte.

---

## Task 13: State Machine extendida + Human Escalation + Crash Recovery

**Status**: pending
**Priority**: high
**Parent ACs**: FR-29, FR-30, FR-37, AC-07, AC-11

### Descripción
En `core/orchestrator.py`:
- Agregar estados: ANALYZE_FAILURE, CONTINUE, STOP.
- `max_steps=1000` global counter que fuerza STOP.
- `HumanEscalation` con: why, what_was_attempted, evidence_exists, human_input_required.
- `try/except (KeyboardInterrupt, Exception)` wrapper: on interrupt → escribir manifest BLOCKED con notes=["interrupted"].
- Límite global retries (3).

### Archivos impactados
- Modificar: `core/orchestrator.py` (DecisionAgent + Orchestrator.run + crash wrapper)

### Test Requirements

#### TR-13.1 (rule) max_steps detiene bucle infinito
State machine con estado que regresa a sí mismo → para en STOP después de max_steps.

#### TR-13.2 (rule) KeyboardInterrupt → manifest BLOCKED
Simular raise KeyboardInterrupt dentro de Orchestrator.run; escribir manifest; quality_gate.status = BLOCKED.

#### TR-13.3 (rule) Escalation tiene 4 campos obligatorios con datos, no vacíos
`Escalation.why` no puede ser "" si status = NEEDS_HUMAN.

### Evidencia
- Bucle programático corto con max_steps=5 → history termina en STOP.

---

## Task 14: Quality Gate + Coverage Engine

**Status**: pending
**Priority**: high
**Parent ACs**: FR-31, FR-32, AC-13, AC-02

### Descripción
Reemplazar `core/quality_gate.py`: QualityGateResult 5 estados (PASS, PASS_WITH_WARNINGS, FAIL, BLOCKED, NEEDS_HUMAN). Calcular: (a) coverage_score = coverage_engine.coverage_ratio(), (b) critical+high findings count, (c) unresolved ratio, (d) blocked tests ratio, (e) flaky ratio, (f) scope limitation flags. Crear `core/coverage_engine.py`: RequirementCoverage, TestCoverage, RiskCoverage, ExecutionCoverage con estados covered/partially_covered/not_covered/blocked/unknown.

### Archivos impactados
- Modificar: `core/quality_gate.py`
- Crear: `core/coverage_engine.py`

### Test Requirements

#### TR-14.1 (rule) Quality Gate 5 estados exclusivos
`QualityGateResult.status ∈ {PASS PASS_WITH_WARNINGS FAIL BLOCKED NEEDS_HUMAN}`. Sólo uno por resultado.

#### TR-14.2 (rule) Coverage states 5 estados
`CoverageState` enum define: covered, partially_covered, not_covered, blocked, unknown.

#### TR-14.3 (rule) 0 findings + 0 tests ejecutados → FAIL o BLOCKED (no PASS)
No se puede aprobar sin cobertura.

### Evidencia
- Evaluación QualityGate sobre findings=[] → reasons no vacío, passed=False.

---

## Task 15: Report Engine + Templates actualizados

**Status**: pending
**Priority**: high
**Parent ACs**: FR-33, AC-18

### Descripción
Extender `core/report_builder.py` para que los 3 formatos (MD/HTML/JSON) incluyan las 20+ secciones. Corregir templates `reports/audit_report.md.jinja` y `reports/audit_report.html.jinja`: usaban campos `.kind`, `.url`, `.detail`; deben usar `.category.value`, `.location`, `.description` del modelo Finding. Agregar secciones: Project Profile, Scope, Environment, Risk Summary, Requirements, Coverage, Tests Planned/Executed, Passed/Failed/Blocked/Flaky, Findings, Evidence, Retries, Escalations, Limitations, Quality Gate, Recommendations, Run Manifest. Mantener Jira exporter.

### Archivos impactados
- Modificar: `core/report_builder.py`
- Modificar: `reports/audit_report.md.jinja`
- Modificar: `reports/audit_report.html.jinja`

### Test Requirements

#### TR-15.1 (rule) MD template contiene al menos 15 de las secciones obligatorias por nombre
Buscar strings en output: "Executive Summary", "Project Profile", "Scope", "Environment", "Risk Summary", "Requirements", "Coverage", "Quality Gate", "Run Manifest".

#### TR-15.2 (rule) Templates acceden a campos correctos de Finding
`audit_report.md.jinja` NO contiene `.kind` ni `.detail` sin fallback; usa `.description` / `.category`.

#### TR-15.3 (rule) JSON output incluye quality_gate + manifest
Keys presentes: "quality_gate", "run_manifest" (o "manifest").

### Evidencia
- Generar reportes con lista dummy de findings y comprobar secciones en strings.

---

## Task 16: Config Profiles + Config Validation + Structured Logging

**Status**: pending
**Priority**: high
**Parent ACs**: FR-35, FR-36, FR-39, FR-40, AC-09

### Descripción
Crear `core/config.py`:
- 4 perfiles: safe (muy conservador: 5 pages, 10 requests, 1 depth, no destructive, no external), standard (default en CLI), deep (ampliado, no destrucción), ci (headless, log level INFO, junit friendly).
- `validate_config(cfg)` fail-fast: max_pages >= 0 (si 0 raise? warning), URL válidas (urlparse), budgets no negativos, riesgo válido, combinaciones inseguras bloqueadas (allow_external + risk_level=high + destructive=true → ValidationError).
- StructuredLogger: niveles DEBUG/INFO/WARNING/ERROR/CRITICAL + run_id contextual. Cada método `logger.info(msg, extra=...)` convierte dict extra a string; PASA por redaction antes de sys.stdout/stderr.

### Archivos impactados
- Crear: `core/config.py` (profiles + validation)
- Crear: `core/logger.py` (structured logging)
- Modificar: imports en orchestrator/main/evidence para usar logger.

### Test Requirements

#### TR-16.1 (rule) 4 perfiles se cargan sin error
`profile_safe(), profile_standard(), profile_deep(), profile_ci()` → dict-like con keys: scope, budget, risk, browser, logging.

#### TR-16.2 (rule) validate_config falla con max_pages = -1
ValidationError / ConfigurationError.

#### TR-16.3 (rule) Logger con run_id redacta tokens
`logger.error("password=abc", run_id="x")` → stdout NO contiene "abc".

### Evidencia
- Config valida 4 perfiles + 1 caso negativo por regla.

---

## Task 17: CLI completa (5 subcomandos)

**Status**: pending
**Priority**: high
**Parent ACs**: FR-34, AC-08

### Descripción
Reescribir `main.py`: subparsers para `discover`, `plan`, `run`, `report`, `validate`. Flags comunes: --scope --budget --browser --headed/--headless --output --risk --dry-run --config.
- `discover <target>`: ejecuta discovery + muestra resumen, NO ejecuta skills.
- `plan <target>`: discovery + requirements + risk + planner → imprime TestPlan summary + JSON.
- `run <target>`: ciclo completo (discover→plan→generate→execute→gate→report).
- `report <run_dir>`: lee RunManifest + findings de una ejecución pasada y regenera HTML/MD/JSON.
- `validate <run_dir>`: valida calidad del run (manifest coherente, artifacts existen, quality gate reproducible).

### Archivos impactados
- Modificar: `main.py` (sustituir build_parser / run_agent actuales)

### Test Requirements

#### TR-17.1 (rule) 5 subcomandos parsean
`build_parser().parse_args(["discover","."])`, `... plan`, `... run`, `... report ./x`, `... validate ./x`.

#### TR-17.2 (rule) `--dry-run` en `run` NO ejecuta skills reales
Sólo plan + print. No se escribe manifest final.

### Evidencia
- Parseo de 5 subcomandos + dry-run sin error sintáctico.

---

## Task 18: Engines existentes blindados (5 engines)

**Status**: pending
**Priority**: high
**Parent ACs**: FR-13..FR-16, NFR-05

### Descripción
Adaptar 5 engines SIN REWRITE, sólo hardening y adaptación de contratos:
- **crawler.py**: normalizar URLs (quitar fragment #, trailing slash unificar), detectar redirect loops (contar redirects por URL < 5), infinite pagination (query params page=n con n>100 cortar), omit_reasons dict, aplicar Budget.consume en cada request, integrar ScopeGuard en links externos.
- **form_tester.py**: payloads existentes (que eran XSS/SQLi literales) se reemplazan por sintácticos harmless bounded (strings marcados `<!--SYN-->`), agregar empty/whitespace/Unicode(1MB max)/malformed/special chars/type_mismatch sets, todo NO destructivo.
- **a11y_auditor.py**: agregar labels for/input association check, buttons sin texto, duplicate IDs en DOM, basic semantic structure (main, nav, section), ARIA check deja de ser "si role= existe = issue" y pasa a lista de roles inválidos/comunes.
- **api_auditor.py**: detect 4xx también, invalid content-type (application/json body no parseable), slow responses (>2s), missing security headers (X-Content-Type-Options, Strict-Transport-Security registrados como missing no como fallos), redirects registrados.
- **report_builder.py**: ya cubierto en Task 15.

Todos adaptan sus findings nativos (CrawlFinding/FormFinding/A11yFinding/ApiFinding) al modelo unificado Finding vía adapter helpers.

### Archivos impactados
- Modificar: `core/crawler.py`
- Modificar: `core/form_tester.py`
- Modificar: `core/a11y_auditor.py`
- Modificar: `core/api_auditor.py`
- Ya cubierto: `core/report_builder.py` (Task 15)

### Test Requirements

#### TR-18.1 (rule) Crawler normaliza URLs sin fragment
`Crawler.extract_links` retorna URLs sin `#hash`.

#### TR-18.2 (rule) Form synthetic payloads NO contienen strings de ataque reales realistas
No hay `<script>alert(1)</script>` literal; en su lugar `<!--SYN:sanitizer_check-->`.

#### TR-18.3 (rule) A11y duplicate IDs detectado
HTML con `<div id="a"><span id="a">` → finding duplicate_ids.

#### TR-18.4 (rule) ApiAuditor.on_response marca 400 como finding
Status 400 → ApiFinding con severity=medium.

### Evidencia
- 4 snippets aislados (uno por engine).

---

## Task 19: Session / Auth Management + Observability helpers

**Status**: pending
**Priority**: medium
**Parent ACs**: FR-17, FR-40

### Descripción
Crear `core/session_manager.py`: soporte para 4 estados anónimo/autenticado/expirado/invalid_credentials. Integracíón con redaction: cookies/tokens/passwords NUNCA pasan al logger o evidence. Crear `core/observability.py`: helpers `why_did_omit(url)`, `budget_remaining(budget)`, `why_retry(retry_count, classification)`, `why_escalate(escalation)` que retornan strings legibles.

### Archivos impactados
- Crear: `core/session_manager.py`
- Crear: `core/observability.py`

### Test Requirements

#### TR-19.1 (rule) SessionManager.get_auth_headers NUNCA devuelve valor real sin redaction wrapper
Loggear headers pasa por redaction automáticamente.

#### TR-19.2 (rule) Observability helpers retornan str no vacío
`budget_remaining` retorna al menos "10 pages left / 5 requests left" con enteros.

### Evidencia
- Instancia SessionManager con credenciales dummy + log no contenga password en claro.

---

## Task 20: Synthetic demo target reproducible

**Status**: pending
**Priority**: medium
**Parent ACs**: FR-44, AC-14

### Descripción
Crear carpeta `demo_target/`:
- `demo_target/index.html`: HTML estático con issues deliberados: (a) href a `/notfound.html` broken link, (b) `<img src="x.png">` sin alt, (c) form con input `<input name="email">` sin `<label for>` asociado, (d) `<button>` vacío sin texto, (e) `<script>console.error("demo synthetic error");</script>` onload, (f) duplicate IDs `<div id="dup"><span id="dup">`.
- `demo_target/app.py`: Python http.server simple con endpoints `/api/slow` (sleep 2s), `/api/ok` (200 json), `/api/err` (500). Ejecutarlo es: `python demo_target/app.py` → localhost:8765. Incluir `demo_target/README.md` (NOTA: éste es el único doc nuevo permitido por ser parte del demo target, no del agente).

### Archivos impactados
- Crear: `demo_target/index.html`
- Crear: `demo_target/app.py`
- Crear: `demo_target/README.md`
- Modificar: `.gitignore` (si fuera necesario, no suele).

### Test Requirements

#### TR-20.1 (rule) index.html contiene al menos 6 issues
Grep/BeautifulSoup en el archivo confirma: broken_link_href, missing_alt, missing_label, empty_button, console_error, duplicate_ids.

#### TR-20.2 (rule) app.py endpoints existen y son syntactic-importables
`from demo_target.app import ...` no falla (o ejecutar `py_compile`).

### Evidencia
- `python -m py_compile demo_target/app.py` exit code 0.
- Conteo de issues.

---

## Task 21: Self-Test architecture (stubs preparados)

**Status**: pending
**Priority**: medium
**Parent ACs**: FR-45

### Descripción
Expandir `tests/` con 9 archivos nuevos (stubs + tests que NO se ejecutan todavía pero preparan estructura). Cada clase TestXxx con 2-3 métodos: smoke import + 1-2 assertions básicas. NO ejecutar pytest. Archivos nuevos:
- tests/test_models.py (validación modelos Task 1)
- tests/test_scope_guard.py (Task 2)
- tests/test_requirements.py (Task 4)
- tests/test_risk_engine.py (Task 5)
- tests/test_failure_analyzer_ext.py (Task 9)
- tests/test_finding_dedup.py (Task 10)
- tests/test_redaction.py (Task 11)
- tests/test_quality_gate_ext.py (Task 14)
- tests/test_crash_recovery.py (Task 13)

### Archivos impactados
- Crear: 9 archivos tests/test_*.py

### Test Requirements

#### TR-21.1 (rule) 9 archivos creados y syntax-valid
`python -m py_compile` en cada uno → 0 errores.

#### TR-21.2 (rule) Cada archivo importa su módulo core correspondiente sin error
Primera línea de test `from core.X import Y` pasa sin ImportError.

### Evidencia
- `py_compile` sobre 9 archivos.

---

## Task 22: README actualizado + Dependency Hygiene + .gitignore

**Status**: pending
**Priority**: medium
**Parent ACs**: FR-46, FR-47, AC-15

### Descripción
- **README.md**: reemplazar por contenido completo: propósito, arquitectura diagrama, instalación, CLI subcommands, configuración (4 profiles), safety model, limitations, example run, report structure, supported targets, troubleshooting, commercial positioning. Incluir explícitamente: "NO reemplaza a un QA humano; es una herramienta de auditoría asistida."
- **requirements.txt**: remover duplicados (actualmente ninguno), confirmar cada dependencia usada (pydantic, playwright, pytest, pytest-asyncio, selectolax, jinja2, httpx). NO agregar librerías nuevas.
- **.gitignore**: agregar `demo_target/__pycache__/`, `demo_target/*.log`, `*.heapprof`, `core/__pycache__/` ya estaba. Asegurar coverage AC-15 (verificar cada pattern).

### Archivos impactados
- Modificar: `README.md`
- Modificar: `requirements.txt` (mantenimiento, no cambios grandes)
- Modificar: `.gitignore`

### Test Requirements

#### TR-22.1 (rule) README contiene 12 secciones obligatorias por nombre
Strings: "Purpose", "Architecture", "Installation", "CLI", "Configuration", "Safety Model", "Limitations", "Example Run", "Report Structure", "Supported Targets", "Troubleshooting", "Commercial Positioning".

#### TR-22.2 (rule) .gitignore contiene patterns para artifacts: screenshots, html reports, json reports, venv, env, logs
Grep en .gitignore: ".venv", ".env", "*.log", "trace.zip", "*.png", "reports/*.html", "reports/*.json", "reports/tmp", "reports/final", "run_manifest.json".

### Evidencia
- Grep outputs.

---

## Task 23: Static Hardening + import cycles + final pre-test review

**Status**: pending
**Priority**: high
**Parent ACs**: FR-48, FR-49, AC-16, AC-17

### Descripción
Revisión estática FINAL:
1. **Broken imports**: todos los archivos core/*.py se importan sin ImportError via `py_compile` + `import core.X`.
2. **Circular imports**: construir un grafo trivial (grep `from core.`), ningún ciclo A→B→A.
3. **Dead code**: funciones/classes no referenciadas → eliminar o comentar TODO.
4. **Duplicate logic**: redaction duplicada → centralizar en Task 11.
5. **Stubs / fake implementations**: handlers que no hacen nada en skills_registry → mantener con comentario "binding stub, real integration en engine".
6. **Critical TODOs**: enumerar en AGENTS.md al final (no eliminar).
7. **Unsafe defaults**: allow_external=True por defecto → cambiar a False si existiera en algún lugar.
8. **Secret leakage**: grep de `password=`, `token=`, `secret=`, `authorization:` en código core → todos pasan por redaction ANTES de write/log.
9. **Unbounded loops**: `while True` sin break condition → agregar max_iter guard.
10. **Unbounded concurrency**: no hay asyncio.Semaphore? → agregar semáforo con default=3 en crawler si fuera necesario.
11. **Incorrect async usage**: funciones async que nunca usan await → marcar sync o agregar comment.
12. **Inconsistent models**: FindingSeverity vs Severity (unificar nombres, mantener alias backward compat).

### Archivos impactados
- Modificar: los archivos core/*.py necesarios según hallazgos.
- Modificar: `AGENTS.md` (añadir sección Critical TODOs al final)

### Test Requirements

#### TR-23.1 (rule) Todos los core/*.py importables
`python -c "import py_compile, os, sys; [py_compile.compile(os.path.join('core',f), doraise=True) for f in os.listdir('core') if f.endswith('.py')]"` → 0 errores.

#### TR-23.2 (rule) No circular imports (A→B→A)
Grep build de dependencias: ningún módulo A importa B que importa A.

#### TR-23.3 (rule) Grep "password" "secret" en core/ devuelve solo ocurrencias en redaction patterns / test data (nunca en hardcoded values)
Si encuentra un valor, eliminar o mover a .env.example pattern.

### Evidencia
- 3 comprobaciones exitosas.

---

## Task 24: FREEZE — estado final para Prompt 2

**Status**: pending
**Priority**: high
**Parent ACs**: AC-01..AC-18

### Descripción
No implementar nada nuevo. Verificación final superficial:
- Todos los archivos creados/modificados enumerados.
- `py_compile` + imports básicos pasan en todos los módulos nuevos.
- CLI parsea 5 subcomandos.
- No se ejecutó pytest suite completa.
- Entrega final en respuesta al usuario: (1) archivos creados, (2) modificados, (3) eliminados, (4) arquitectura implementada, (5) capacidades nuevas, (6) integraciones realizadas, (7) controles de seguridad, (8) componentes pendientes si existen, (9) estado.
- NO declarar READY.
- NO correr tests.

### Test Requirements

#### TR-24.1 (rule) Resumen de entrega lista con 9 puntos mencionados en prompt
Cumplir formato del punto 53.

#### TR-24.2 (rule) NUNCA se ejecutó `pytest -vv` completo en esta fase
Historial de comandos (auto-reportado) → NO aparece `pytest -vv` ni `pytest` sin flags restrictivos.

### Evidencia
- Output final del asistente con punto 53 completo.

---

## Dependency order

```
Task 1 (models) ─┐
                 ├─ Task 2 (scope/budget/governor)
                 ├─ Task 3 (discovery) ─┐
                 │                      ├─ Task 4 (requirements + spec)
                 │                      └─ Task 5 (risk engine)
                 │                         ├─ Task 6 (planner + generator)
                 ├─ Task 7 (registry/actions) ──┐
                 ├─ Task 11 (redaction) ──┤      │
Task 11 (redact) ─┼──────────────────────┤      │
                 │                      Task 10 (findings/evidence)
                 │                      Task 9 (failure/retry/flaky)
                 │                      Task 8 (executor)
                 ├─ Task 12 (manifest/atomic)
                 ├─ Task 16 (config/logger)
                 │                      Task 14 (quality/coverage)
                 │                      Task 15 (report/templates)
                 │                      Task 13 (orchestrator/state/escalation)
                 │                      Task 17 (CLI)
                 │                      Task 18 (engines hardening)
                 │                      Task 19 (session/observability)
                 │                      Task 20 (demo target)
                 │                      Task 21 (self-test stubs)
                 │                      Task 22 (README/.gitignore/deps)
                 │                      Task 23 (static hardening)
                 └────────────────────── Task 24 (FREEZE)
```

Parallel safe groups (no escriben mismos archivos):
- **Group A**: Task 1 (solo)
- **Group B**: Tasks 2, 3, 7, 11, 12, 16
- **Group C**: Tasks 4, 5, 6
- **Group D**: Tasks 9, 10, 8, 14, 15
- **Group E**: Tasks 13, 17, 18, 19
- **Group F**: Tasks 20, 21, 22
- **Final**: Tasks 23, 24
