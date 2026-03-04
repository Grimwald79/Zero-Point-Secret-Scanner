# Zero Point Secret Scanner

An automated, local, Pre-Commit Secret Scanner engineered to prevent high-entropy cryptographic keys and API tokens from entering your Git history.

Unlike traditional secret scanners that rely heavily on fragile Regular Expressions (Regex), this tool leverages a combination of **Shannon Entropy Mathematics** and **Abstract Syntax Tree (AST) Parsing** to semantically understand your code and drastically reduce false positives.

## 🧠 The Architecture: Why AST + Entropy?

Most secret scanners use regex to look for keywords like `secret` or `password`. This leads to "Alert Fatigue" when natural language strings or docstrings trigger false alarms.

This scanner takes a "Skill-Based" approach:

1. **Semantic Understanding (AST):** The scanner uses Python's native `ast` module (`ast.walk`). It ignores variable names, function definitions, and comments. It *only* evaluates the literal values assigned in your code (`ast.Constant`).

2. **Mathematical Randomness (Shannon Entropy):** If a string is evaluated, we calculate its Shannon Entropy ($H = -\sum p_i \log_2 p_i$). Cryptographic keys (like AWS access keys) have a high entropy score due to character randomness.

3. **Structural Heuristics:** To prevent long English sentences from triggering the entropy threshold, the scanner explicitly filters out strings containing whitespace.

## 🛡️ Threat Model Mitigations Built-In

* **No Command Injection:** Subprocess calls to Git utilize strict list-based arguments with `shell=False`.

* **DoS Prevention:** File size limits (500 KB default) are enforced before memory allocation to the AST parser.

* **Information Disclosure Prevention:** Discovered secrets are locally masked (`AKI...[MASKED]...PLE`) before being written to the generated Markdown report.

* **Path Traversal Protection:** All local file generation utilizes strict path resolution limits.

## ⚙️ Requirements

* **Python:** 3.12+ (Utilizes modern type hints and syntax)

* **Git:** Must be initialized in your repository

* **OS:** Cross-platform (Windows, macOS, Linux)

## 🚀 Installation & Setup

You do not need to configure complex CI/CD pipelines to start defending your local repository. The included installer dynamically generates a Git hook that intercepts your commits.

1. **Clone or copy the scripts into your repository root:**
   Ensure `secret_scanner.py` and `install_hook.py` are present.

2. **Run the Hook Installer:**

*git add .*

*git commit -m "feat: added new S3 connection logic"*

### The "Happy Path" (Clean Code)

If no secrets are detected, the commit will proceed silently and normally.

### The "Blocked Path" (Secrets Detected)

If you accidentally staged a high-entropy API token, the scanner will intercept the commit lifecycle and abort the operation:

*[+] Running Zero Point Secret Scanner...*


*--- Running Automated Verification Suite ---*

*[PASS] Entropy calculations are mathematically sound.*

*[PASS] Secret masking prevents local data leaks.*

*[PASS] AST Scanner accurately isolates high-entropy constants.*

*--- Verification Complete ---*


*[+] Starting Pre-Commit Secret Scan...*
*[!] Found 1 potential secrets. Report written to /path/to/secrets_report.md*

*[!] COMMIT REJECTED: Secrets detected. Review the markdown report.*
*[-] Commit aborted by Secret Scanner.*

Open the generated `secrets_report.md` to see exactly which file and line number caused the violation, mask the secret in your code, stage the changes, and commit again.

## 🧪 Automated Verification (Protocol 10)

This tool assumes code is guilty until proven innocent. Every time the scanner runs, it first executes an internal test suite asserting that the Shannon Entropy math is correctly calibrated and the AST parser is successfully isolating constants. If the math fails, the scanner safely aborts to protect your pipeline.

## 📜 License & Educational Disclaimer

This is an educational tool designed to demonstrate the mechanics of Static Application Security Testing (SAST). For enterprise-grade distributed scanning, consider incorporating this logic into a centralized `.pre-commit-config.yaml` framework.
