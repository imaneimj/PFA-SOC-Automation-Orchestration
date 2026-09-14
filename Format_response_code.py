import json
import ast
import re

raw = '''$final_decision.body.response'''

normalized = re.sub(r'\btrue\b', 'True', raw)
normalized = re.sub(r'\bfalse\b', 'False', normalized)
normalized = re.sub(r'\bnull\b', 'None', normalized)

try:
    response = ast.literal_eval(normalized)
except Exception as e:
    raise Exception(f"Unable to parse response: {e}")

if not isinstance(response, dict):
    raise Exception("Response is not a dictionary")

output = {
    "response": {
        "automatic": bool(response.get("automatic", False)),
        "actions": response.get("actions", [])
    }
}

print(json.dumps(output))