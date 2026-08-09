from __future__ import annotations

from pathlib import Path

from xdr_graph.runtime_security import validate_configuration


REQUIRED_DOCUMENTS = ("README.md", "PROJECT_ROADMAP.md", "docs/SECURITY.md")


def validate_release_tree(project_root: str | Path) -> list[str]:
    root = Path(project_root)
    errors = validate_configuration(root / "config")
    for relative_path in REQUIRED_DOCUMENTS:
        path = root / relative_path
        if not path.is_file():
            errors.append(f"missing required document: {relative_path}")
            continue
        try:
            path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            errors.append(f"document is not valid UTF-8: {relative_path}")
    return errors
