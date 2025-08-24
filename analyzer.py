from __future__ import annotations
import argparse
from typing import List

from engine import rules as rules_engine
from engine import formats
from engine import model as model_engine

def main():
    ap = argparse.ArgumentParser(description="Local C/C++ vulnerability analyzer (rules + optional local LLM).")
    ap.add_argument("path", help="Path to a C/C++ source file")
    ap.add_argument("--json", action="store_true", help="Output JSON")
    ap.add_argument("--no-llm", action="store_true", help="Disable local LLM explanations")
    ap.add_argument("--context", type=int, default=3, help="Context lines for LLM prompt (not used in rules-only mode)")
    ap.add_argument("--rules", type=str, default="", help="Comma-separated rule names to enable")
    args = ap.parse_args()

    with open(args.path, "r", encoding="utf-8", errors="ignore") as f:
        src = f.read()

    enabled_rules: List[str] | None = None
    if args.rules.strip():
        enabled_rules = [r.strip() for r in args.rules.split(",") if r.strip()]

    findings = rules_engine.analyze(src, enabled_rules)
    if not args.no_llm:
        for f in findings:
            expl = model_engine.explain(f.get("snippet",""), f.get("rule","Finding"))
            if expl:
                f["llm_explanation"] = expl
            f.setdefault("fix", "No fix available.")

    if not findings:
        message = f"Analysis Complete: No security or memory issues detected in '{args.path}'."
        if args.json:
            import json
            print(json.dumps({"message": message}, indent=2))
        else:
            print(message)
        return

    if args.json:
        formats.print_json(findings)
    else:
        print_text_with_fixes(findings)


def print_text_with_fixes(findings):
    for f in findings:
        line = f.get("line", "?")
        rule = f.get("rule", "Finding")
        msg = f.get("message", "")
        snippet = f.get("snippet", "")
        fix = f.get("fix", "No fix available.")
        llm_expl = f.get("llm_explanation", "")

        print(f"Line {line} | Rule: {rule}")
        print(f"Message: {msg}")
        if snippet:
            print("Snippet:")
            print(f"  {snippet}")
        if fix:
            print(f"Suggested Fix: {fix}")
        if llm_expl:
            print(f"LLM Explanation: {llm_expl}")
        print("-" * 80)


if __name__ == "__main__":
    main()
