"""ArtifactIQ entry point: python app.py"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from artifactiq import create_app
from artifactiq.config import Config
from artifactiq.db import init_db


def main() -> None:
    app = create_app()
    init_db(app.config["DB_PATH"])
    print(f"ArtifactIQ {Config.VERSION} running on http://{Config.HOST}:{Config.PORT} "
          f"(data dir: {Path(Config.DB_PATH).parent})")
    print("Forensics notice: never bind this tool to a public interface.")
    app.run(host=Config.HOST, port=Config.PORT, debug=Config.DEBUG)


if __name__ == "__main__":
    main()
