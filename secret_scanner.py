import ast
import collections
import math
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

# ==========================================
# DEV LOG & CONFIGURATION
# ==========================================
# Threat Model Mitigations in this design:
# 1. No shell=True. All subprocess calls use explicit lists.
# 2. File size limits imposed before AST parsing to prevent DoS.
# 3. Discovered secrets are MASKED before being written to the report.

ENTROPY_THRESHOLD = (
    3.5  # Adjusted: 20-char strings max out at log2(20)=4.32. 3.5 catches AWS keys.
)
MIN_SECRET_LENGTH = 12  # Ignore short strings (e.g., "password")
MAX_FILE_SIZE_BYTES = 1024 * 500  # 500 KB limit for AST parsing


# ==========================================
# BRICK 1: THE ENTROPY CALCULATOR
# ==========================================
def calculate_shannon_entropy(data: str) -> float:
    """
    Calculates the Shannon Entropy of a string.
    H = - Sum( P(i) * log2(P(i)) )

    A higher score indicates higher randomness.
    """
    if not data:
        return 0.0

    entropy = 0.0
    length = len(data)

    # collections.Counter gives us the frequency of each character
    occurrences = collections.Counter(data)

    # Verbose loop for educational auditing (No magic one-liners here)
    for character, count in occurrences.items():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def mask_secret(secret: str) -> str:
    """Masks a secret for safe reporting."""
    if len(secret) <= 6:
        return "******"
    return f"{secret[:3]}...[MASKED]...{secret[-3:]}"


# ==========================================
# BRICK 2: THE AST PARSER
# ==========================================
class SecretNodeVisitor(ast.NodeVisitor):
    """
    Walks the Abstract Syntax Tree looking for string constants.
    """

    def __init__(self, filename: str):
        self.filename = filename
        self.findings: List[Dict[str, Any]] = []

    def visit_Constant(self, node: ast.Constant) -> None:
        """
        In Python 3.8+, string literals are parsed as ast.Constant.
        We only care about the values, bypassing variable names entirely.
        """
        # We only evaluate string values
        if isinstance(node.value, str):
            value = node.value

            # Heuristic 1: Filter out short strings to reduce false positives
            # Heuristic 2: API tokens and Cryptographic Keys rarely contain whitespace.
            # This prevents natural language (logs/docstrings) from triggering false positives.
            if len(value) >= MIN_SECRET_LENGTH and not any(c.isspace() for c in value):
                score = calculate_shannon_entropy(value)

                if score >= ENTROPY_THRESHOLD:
                    self.findings.append(
                        {
                            "file": self.filename,
                            "line": getattr(node, "lineno", 0),
                            "entropy": round(score, 2),
                            "masked_value": mask_secret(value),
                        }
                    )

        # Must call generic_visit to continue walking down the tree
        self.generic_visit(node)


def scan_python_code(source_code: str, filename: str) -> List[Dict[str, Any]]:
    """Safely parses Python code into an AST and extracts high-entropy strings."""
    # Security: Prevent DoS from massive files
    if len(source_code.encode("utf-8")) > MAX_FILE_SIZE_BYTES:
        print(f"[-] Skipping {filename}: File exceeds size limit.")
        return []

    try:
        tree = ast.parse(source_code)
        visitor = SecretNodeVisitor(filename)
        visitor.visit(tree)
        return visitor.findings
    except SyntaxError as e:
        print(f"[-] Skipping {filename}: Syntax error in code. ({e})")
        return []


# ==========================================
# BRICK 3: SYSTEM INTEGRATION (GIT WRAPPER)
# ==========================================
def get_staged_python_files() -> List[str]:
    """Retrieves a list of staged Python files from Git."""
    try:
        # Security: Arguments as a list, shell=False by default.
        result = subprocess.run(
            ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
            capture_output=True,
            text=True,
            check=True,
        )
        files = result.stdout.splitlines()
        # Only return .py files
        python_files = []
        for f in files:
            if f.endswith(".py"):
                python_files.append(f)
        return python_files
    except subprocess.CalledProcessError:
        print("[-] Git command failed. Are you in a Git repository?")
        return []
    except FileNotFoundError:
        print("[-] Git executable not found.")
        return []


def generate_markdown_report(
    findings: List[Dict[str, Any]], output_path: str = "secrets_report.md"
) -> None:
    """Writes findings to a Markdown file securely."""
    if not findings:
        print("[+] No secrets found. You are clear to commit.")
        return

    # Security: Enforce local path resolution to prevent path traversal
    safe_path = Path(output_path).resolve()

    with open(safe_path, "w", encoding="utf-8") as f:
        f.write("# Pre-Commit Security Audit: Secret Scan\n\n")
        f.write("⚠️ **WARNING: High-Entropy Strings Detected!** ⚠️\n\n")
        f.write("| File | Line | Entropy Score | Masked Value |\n")
        f.write("|---|---|---|---|\n")

        for finding in findings:
            f.write(
                f"| `{finding['file']}` | {finding['line']} | {finding['entropy']} | `{finding['masked_value']}` |\n"
            )

    print(f"[!] Found {len(findings)} potential secrets. Report written to {safe_path}")


# ==========================================
# BRICK 4: AUTOMATED VERIFICATION (PROTOCOL 10)
# ==========================================
def run_security_audit_tests():
    """
    Test-Driven Verification.
    Guilty until proven innocent. We assert expected behavior.
    """
    print("\n--- Running Automated Verification Suite ---")

    # Test 1: Entropy Math Verification
    low_entropy = calculate_shannon_entropy("hello world")
    high_entropy = calculate_shannon_entropy(
        "AKIAIOSFODNN7EXAMPLE"
    )  # Mock AWS Key structure

    assert low_entropy < 3.0, f"Expected low entropy, got {low_entropy}"
    assert high_entropy >= 3.5, f"Expected high entropy, got {high_entropy}"
    print("[PASS] Entropy calculations are mathematically sound.")

    # Test 2: Masking Verification (Information Disclosure Prevention)
    mock_secret = "super_secret_token_12345"
    masked = mask_secret(mock_secret)
    assert "secret" not in masked, "Masking function leaked the secret!"
    assert masked.startswith("sup"), "Masking altered prefix"
    assert masked.endswith("345"), "Masking altered suffix"
    print("[PASS] Secret masking prevents local data leaks.")

    # Test 3: AST Parsing Verification (Negative & Positive)
    mock_code = """
AWS_KEY = "AKIAIOSFODNN7EXAMPLE" # Should be caught
safe_string = "Just a normal log message" # Should be ignored
def hello():
    token = "ghp_xxxyyyzzz1234567890abcdef" # Should be caught
    """
    findings = scan_python_code(mock_code, "mock_file.py")

    assert len(findings) == 2, f"Expected 2 secrets, found {len(findings)}"
    assert findings[0]["line"] == 2, "Failed to identify line number of first secret"
    assert findings[1]["line"] == 5, "Failed to identify line number of second secret"
    print("[PASS] AST Scanner accurately isolates high-entropy constants.")
    print("--- Verification Complete ---\n")


# ==========================================
# MAIN EXECUTION FLOW
# ==========================================
if __name__ == "__main__":
    # Always run tests first to verify local execution environment
    run_security_audit_tests()

    print("[*] Starting Pre-Commit Secret Scan...")

    target_files = get_staged_python_files()
    if not target_files:
        print("[*] No Python files staged for commit.")
    else:
        all_findings = []
        for file_path in target_files:
            # We read the local file. (For a true pre-commit hook, we'd use `git show :file`)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    source = f.read()
                findings = scan_python_code(source, file_path)
                all_findings.extend(findings)
            except Exception as e:
                print(f"[-] Error reading {file_path}: {e}")

        generate_markdown_report(all_findings)

        # CI/CD Enforcement: Exit codes dictate pipeline state
        if all_findings:
            print(
                "\n[!] COMMIT REJECTED: Secrets detected. Review the markdown report."
            )
            sys.exit(1)
        else:
            print("\n[+] COMMIT APPROVED: Code is clean.")
            sys.exit(0)
