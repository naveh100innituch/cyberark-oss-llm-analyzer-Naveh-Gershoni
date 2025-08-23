from llama_cpp import Llama
import os

_llm = None

def _init_llm():
    global _llm
    if _llm is None:
        model_path = os.environ.get("MODEL_PATH")
        if not model_path or not os.path.exists(model_path):
            raise ValueError(f"Model path does not exist: {model_path}")
        _llm = Llama(model_path=model_path, n_ctx=4096, n_threads=4, verbose=False)

def explain(snippet: str, rule_name: str) -> str:
    """
    Generate an explanation for a code snippet using the local LLM.
    """
    _init_llm()

    prompt = f"""
You are a cybersecurity analyzer. Explain the following C/C++ code vulnerability.

Rule: {rule_name}
Code:
{snippet}

Provide a clear, concise explanation:
"""
    result = _llm(prompt)
    
    if isinstance(result, tuple):
        text = result[0]
    else:
        text = result
    if isinstance(text, dict):
        return text.get("explanation", "")
    return text

