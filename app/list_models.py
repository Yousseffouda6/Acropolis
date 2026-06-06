"""List every Gemini model available to your API key that supports generateContent.

Run from the app/ directory:
    python list_models.py
"""
import json
import os
import urllib.request

from dotenv import load_dotenv

load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))

api_key = os.environ.get("GEMINI_API_KEY", "")
if not api_key:
    print("ERROR: GEMINI_API_KEY not set - add it to app/.env")
    raise SystemExit(1)

url = f"https://generativelanguage.googleapis.com/v1beta/models?key={api_key}"
with urllib.request.urlopen(url) as resp:
    data = json.loads(resp.read())

print(f"{'Model name':<45} {'Display name'}")
print("-" * 75)
for m in data.get("models", []):
    if "generateContent" in m.get("supportedGenerationMethods", []):
        name = m["name"].replace("models/", "")
        display = m.get("displayName", "")
        print(f"{name:<45} {display}")
