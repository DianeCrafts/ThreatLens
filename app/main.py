from __future__ import annotations

from pathlib import Path

from app.runner import run


def main() -> None:
    project_root = Path(__file__).resolve().parent.parent
    config_path = project_root / "config" / "settings.yaml"
    run(config_path)


if __name__ == "__main__":
    main()
