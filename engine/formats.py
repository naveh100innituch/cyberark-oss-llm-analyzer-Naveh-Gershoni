
from __future__ import annotations
import json
from typing import List, Dict, Any

def print_text(findings: List[Dict[str, Any]]) -> None:
    for f in findings:
        line = f.get("line", "?")
        msg = f.get("message", "")
        print(f"Line {line}: {msg}")

def print_json(findings: List[Dict[str, Any]]) -> None:
    print(json.dumps(findings, indent=2, ensure_ascii=False))
