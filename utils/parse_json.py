# services/json_utils.py
import json
import re

def force_json(text: str) -> dict:
    # Extract the first {...} block to be safe
    m = re.search(r"\{.*\}", text, flags=re.S)
    if not m:
        raise ValueError("No JSON object found in LLM output.")
    candidate = m.group(0)
    return json.loads(candidate)
