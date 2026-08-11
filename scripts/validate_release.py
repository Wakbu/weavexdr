from pathlib import Path

from xdr_graph.release_validation import validate_release_tree, validate_update_manifest, validate_windows_package


def main() -> int:
    project_root = Path(__file__).resolve().parents[1]
    errors = validate_release_tree(project_root)
    packages = sorted((project_root / "dist").glob("weavexdr-*-windows.zip"))
    if packages:
        errors.extend(validate_windows_package(packages[-1]))
        version = packages[-1].name.removeprefix("weavexdr-").removesuffix("-windows.zip")
        errors.extend(validate_update_manifest(project_root / "dist" / f"weavexdr-{version}-manifest.json"))
    if errors:
        for error in errors:
            print(f"ERROR: {error}")
        return 1
    print("Release tree validation passed / 릴리스 트리 검증 통과")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
