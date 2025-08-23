
from engine.rules import analyze

def test_detects_basic_patterns():
    src = "char *tmp = new char[64];\nmemcpy(tmp, data, len);\n"
    f = analyze(src)
    assert any(x["rule"] == "HEAP_OVERFLOW" for x in f)
