# Form boundary test

Purpose: defensive form probing with boundary and synthetic payloads.
Inputs: discovered form fields, Scope, Budget.
Outputs: form findings and payload counts.
Privacy: payloads stay local; redact credentials before evidence write.
Engine: `core.form_tester`.
