import os
import stat
import sys
from pathlib import Path


def install_git_hook():
    """
    Automates the creation of a Git pre-commit hook.
    Binds our Python scanner to the git commit lifecycle.
    """
    hook_dir = Path(".git/hooks")

    if not hook_dir.exists():
        print("[-] Error: .git/hooks directory not found. Initialize git first.")
        sys.exit(1)

    hook_path = hook_dir / "pre-commit"

    # We write a bash script because Git internal logic is Unix-based,
    # even when running on Windows (via Git Bash/MinGW).
    # NOTE: Ensure the python filename here matches what you named it locally!
    hook_script = """#!/usr/bin/env bash
echo "[*] Running Zero Point Secret Scanner..."

# Execute the python scanner
python secret_scanner.py 

# Capture the exit code of the python script
SCANNER_EXIT_CODE=$?

# If the python script exited with 1, abort the commit
if [ $SCANNER_EXIT_CODE -ne 0 ]; then
    echo "[-] Commit aborted by Secret Scanner."
    exit 1
fi
"""
    try:
        # Write the file with explicit Unix newlines
        with open(hook_path, "w", newline="\n") as f:
            f.write(hook_script)

        # Make the hook executable (chmod +x)
        st = os.stat(hook_path)
        os.chmod(hook_path, st.st_mode | stat.S_IEXEC)

        print(f"[+] Successfully installed pre-commit hook at: {hook_path}")
        print("[+] Your repository is now actively defended.")
    except Exception as e:
        print(f"[-] Failed to install hook: {e}")


if __name__ == "__main__":
    install_git_hook()
