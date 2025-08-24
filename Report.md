# Report
Work Process Report
1. Initial Analysis and Understanding

The first step was to fully understand the objectives of the exercise. The goal was to set up and test the CyberArk OSS LLM Analyzer for C/C++ code vulnerabilities and integrate it with both local and Docker-based workflows. I carefully reviewed the source code, test cases, and existing regular expressions that detect vulnerabilities.

2. Environment Setup

I ensured that Python 3.10+ was installed on my system.

Installed all required dependencies from requirements.txt.

Verified the location of the LLM model (gemma-3-1b-it.fp16.gguf) to make sure it would work both locally and in Docker.

3. Understanding the Regular Expressions

I examined all regex patterns used to detect various C/C++ code vulnerabilities (e.g., DOUBLE_FREE, NULL_DEREF, MEM_LEAK).

I identified patterns that were not catching the intended cases.

Decided not to modify the model but adjusted the environment and paths to ensure proper execution.

Added rules as much as i could.

4. Testing Locally

Ran tests in the Python environment using pytest to check which rules passed or failed.

Identified that some critical tests (DOUBLE_FREE, NULL_DEREF) were failing due to incorrect pathing or missing model access.

5. Docker Integration

Built a Docker image for the analyzer to ensure portability and reproducibility.

Mapped local code and model directories correctly into the container.

Faced challenges with Windows path syntax and environment variable passing.

Verified that the analyzer ran successfully in the container once paths were correctly configured.

6. Quick Start and Documentation

Created a Quick Start guide for both local and Docker usage.

Ensured instructions included all prerequisites, example commands, and notes about the model file.

7. Decision-Making Highlights

Model Path: Decided not to alter the model path hardcoded in model.py; instead, I adapted the Docker environment to accommodate it.

Performance: Considered multi-threading for faster analysis but prioritized correct functionality first , but it only helped managing coples of file simultanously and didnt cut the runtime so I used 1threaded program.

Docker vs Local: Documented both approaches to give flexibility to users.

Testing: Focused on passing core vulnerability tests, while accepting that regex-based detection may not catch all edge cases.

Samples: Added some samples of my own

8. Conclusion

The work process was methodical:

Understand requirements, setup environment, consider approch ways to detect vuln's, debug failing tests,integrate Docker, document usage, final verification.
This approach ensured that the analyzer could run reliably in different environments and that users have clear instructions to follow.