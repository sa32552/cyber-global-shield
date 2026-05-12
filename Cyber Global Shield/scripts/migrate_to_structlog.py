#!/usr/bin/env python3
"""
Script de migration massive de logging → structlog pour Cyber Global Shield.
Remplace 'import logging' et 'logger = logging.getLogger(...)' par structlog.
Usage: python scripts/migrate_to_structlog.py
"""
import os
import re
import fnmatch

EXCLUDE_DIRS = {"__pycache__", ".git", "venv", "node_modules", ".venv"}
EXCLUDE_FILES = {"__init__.py"}

BASE_DIR = os.path.join(os.path.dirname(__file__), "..")

# Pattern: import logging (standalone)
IMPORT_LOGGING_PAT = re.compile(r"^import logging$", re.MULTILINE)

# Pattern: from logging import ...
FROM_LOGGING_PAT = re.compile(r"^from logging import", re.MULTILINE)

# Pattern: logger = logging.getLogger(__name__)
LOGGER_PAT = re.compile(
    r"^logger\s*=\s*logging\.getLogger\(__name__\)$", re.MULTILINE
)

# Pattern: logging.<method>(...)
LOGGING_CALL_PAT = re.compile(r"logging\.(debug|info|warning|error|critical|exception)\(")

STRUCTLOG_IMPORT = "import structlog\n"
STRUCTLOG_LOGGER = 'logger = structlog.get_logger(__name__)'


def should_process(filepath: str) -> bool:
    """Check if file should be processed."""
    filename = os.path.basename(filepath)
    if filename in EXCLUDE_FILES:
        return False
    if not filename.endswith(".py"):
        return False
    for part in filepath.replace("\\", "/").split("/"):
        if part in EXCLUDE_DIRS:
            return False
    return True


def migrate_file(filepath: str) -> bool:
    """Migrate a single file from logging to structlog. Returns True if modified."""
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()

    original = content
    modified = False

    # 1. Replace 'import logging' with 'import structlog'
    if IMPORT_LOGGING_PAT.search(content):
        content = IMPORT_LOGGING_PAT.sub("import structlog", content)
        modified = True

    # 2. Replace 'from logging import ...' with 'import structlog'
    if FROM_LOGGING_PAT.search(content):
        content = FROM_LOGGING_PAT.sub("import structlog", content)
        modified = True

    # 3. Replace 'logger = logging.getLogger(__name__)'
    if LOGGER_PAT.search(content):
        content = LOGGER_PAT.sub(STRUCTLOG_LOGGER, content)
        modified = True

    # 4. Replace 'logging.<method>(...)' with 'logger.<method>(...)'
    #    Only if the file already uses 'logger' variable
    if "logger." in content:
        content = LOGGING_CALL_PAT.sub(r"logger.\1(", content)
        modified = True

    if modified and content != original:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)
        return True

    return False


def main():
    modified_files = []
    skipped_files = []

    for root, dirs, files in os.walk(BASE_DIR):
        # Skip excluded directories
        dirs[:] = [d for d in dirs if d not in EXCLUDE_DIRS]

        for filename in files:
            filepath = os.path.join(root, filename)
            if not should_process(filepath):
                continue

            try:
                if migrate_file(filepath):
                    modified_files.append(filepath)
                    print(f"  ✅ {os.path.relpath(filepath, BASE_DIR)}")
            except Exception as e:
                skipped_files.append((filepath, str(e)))
                print(f"  ❌ {os.path.relpath(filepath, BASE_DIR)}: {e}")

    print(f"\n{'='*60}")
    print(f"Migration terminée !")
    print(f"  Fichiers modifiés : {len(modified_files)}")
    print(f"  Fichiers ignorés  : {len(skipped_files)}")

    if skipped_files:
        print(f"\nErreurs :")
        for fp, err in skipped_files:
            print(f"  - {fp}: {err}")


if __name__ == "__main__":
    main()
