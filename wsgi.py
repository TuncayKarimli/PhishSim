"""Production WSGI entry point.

Run with Gunicorn:
    gunicorn -w 4 -b 0.0.0.0:5000 wsgi:app
"""
import os

from app import create_app
from app.scheduler import start_scheduler
from config import Config

app = create_app(Config)

# Start the background scheduler unless explicitly disabled (e.g. when running a
# dedicated `python worker.py` container). `start_scheduler` acquires an OS file
# lock so only one Gunicorn worker will run the scheduler.
if os.getenv("RUN_SCHEDULER", "true").strip().lower() not in {"0", "false", "no", "off"}:
    start_scheduler(app)
