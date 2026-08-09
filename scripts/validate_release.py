from pathlib import Path

from xdr_graph.release_validation import validate_release_tree


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    errors = validate_release_tree(project_root)
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("Release tree validation passed / 릴리스 트리 검증 통과")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
