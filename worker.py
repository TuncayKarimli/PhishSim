"""Standalone background scheduler employee for multi-container deployments.

Run with:
    python worker.py
"""
import signal
import time

from app import create_app
from app.scheduler import start_scheduler
from config import Config

app = create_app(Config)


def main():
    scheduler = start_scheduler(app)
    running = True

    def _stop(signum, frame):
        nonlocal running
        running = False
        if scheduler:
            scheduler.shutdown(wait=False)

    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    while running:
        time.sleep(1)


if __name__ == "__main__":
    main()
