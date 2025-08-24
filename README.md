# cyberark-oss-llm-analyzer
## Project Overview
CyberArk OSS LLM Analyzer is a tool for static analysis of C/C++ code. It leverages a local LLM (Large Language Model) to provide explanations for potential vulnerabilities found in code. The analyzer detects various types of issues, such as memory leaks, double frees, null pointer dereferences, unsafe casts, and hardcoded secrets.

The project is modular and consists of the following main components:

- **Engine**: Handles vulnerability detection rules and manages the LLM integration.
- **Model**: Wraps the local LLM and provides explanations for findings.
- **CLI**: Command-line interface to run the analyzer on code files.
- **Rules**: Set of regex-based and logic-based detection rules for various C/C++ vulnerabilities.
- **Sample**: Example code snippets to test the analyzer.
- **Tests**: For the correctness of the code.

## Quick Start
- Run Locally (Without Docker):
    1. Prerequisites: Python 3.10+ installed
    Required Python packages: pip install -r requirements.txt
    2. Set your model path in engine/model.py (already set to local model).
    3. Run the analyzer on a C/C++ file: python analyzer.py /path/to/your/codefile.cpp (I have created cople of samples for tests)

- Run with Docker:
    1. Prerequisites: Make sure Docker is installed on your system.
    2. Build the Docker image: docker build -t cpp-analyzer .
    3. Run the analyzer on a C/C++ file: docker run --rm -v "C:\Users\המחשב שלי\Downloads\cyberark-oss-llm-analyzer\cyberark-oss-llm-analyzer:/home/vulnuser/app" -e MODEL_PATH="/home/vulnuser/app/models/gemma-3-1b-it.fp16.gguf" vuln-analyzer /home/vulnuser/app//path/to/your/codefile.cpp
    (I have created cople of samples for tests) - 

## Notes
    1. I did both bonuses
    2. I didn't notice the note that it is important to see progress through the commits. I worked on the file from my computer until the bonus stage and then uploaded everything to Git, so I don't see commits until the bonus task. The progress and improvements I had along the way are detailed in the report file.
    3. My runtimes are a bit long because I gave a large number of rules that aim to identify vulnerabilities - about 60, and in addition, I examined the context of each suspicious line of code (at the 3-line level) in order to understand the context and focus precisely on the work - I saw fit to focus on exposing as many weaknesses as possible with maximum accuracy as a substitute for runtimes.
