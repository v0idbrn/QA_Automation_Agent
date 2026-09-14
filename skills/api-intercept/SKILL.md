# API intercept

Purpose: observe backend HTTP errors and malformed JSON during a run.
Inputs: intercepted request/response pairs.
Outputs: API findings with redacted headers/bodies.
Privacy: Authorization, cookies, and tokens are redacted before persistence.
Engine: `core.api_auditor`.
