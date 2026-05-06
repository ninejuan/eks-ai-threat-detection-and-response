import json
import re


def extract_json(text: str) -> dict:
    text = text.strip()

    if text.startswith("{"):
        end = text.rfind("}")
        if end != -1:
            try:
                return json.loads(text[: end + 1])
            except json.JSONDecodeError:
                pass

    match = re.search(r"```(?:json)?\s*\n?(.*?)\n?```", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(1).strip())
        except json.JSONDecodeError:
            pass

    match = re.search(r"\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}", text, re.DOTALL)
    if match:
        try:
            return json.loads(match.group(0))
        except json.JSONDecodeError:
            pass

    raise json.JSONDecodeError("No valid JSON found in response", text, 0)
