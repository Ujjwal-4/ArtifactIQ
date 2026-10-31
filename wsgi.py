"""WSGI entry point for hosting platforms.

Local run stays `python app.py`; platforms that inject a START command use:
    gunicorn -w 1 -b 0.0.0.0:$PORT wsgi:app
One worker: SQLite-backed, single-investigator tool by design.
"""
from artifactiq import create_app

app = create_app()

if __name__ == "__main__":
    app.run()
