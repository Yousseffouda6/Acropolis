# ai-security/

This directory is a **pointer**. Acropolis's AI/LLM security work (Phase 6) was
built *into the application*, not as a standalone module — which is the point:
the LLM flaws share the same request path, session, and data as every other
Acropolis vulnerability.

Where the work actually lives:

- **The feature** — the `/ai` assistant (Google Gemini + local Ollama backends):
  [`../app/app.py`](../app/app.py) and its template
  [`../app/templates/ai.html`](../app/templates/ai.html).
- **The red-team notes** — five planted flaws mapped to the OWASP Top 10 for LLM
  Applications, plus the Gemini-vs-TinyLlama comparison:
  [`../writeups/phase-6-ai-llm.md`](../writeups/phase-6-ai-llm.md).
- **The remediation** — how those five flaws were fixed in Phase 8:
  [`../writeups/phase-8-remediation.md`](../writeups/phase-8-remediation.md).
