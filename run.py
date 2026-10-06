"""Entry point. Run with:  python run.py"""
import os

num=1

from app import create_app
from app.scheduler import start_scheduler
from config import Config

app = create_app(Config)

if __name__ == "__main__":
    is_debug = app.config.get("ENV", "development") != "production"
    # Start the background scheduler once (the debug reloader spawns a child
    # process; WERKZEUG_RUN_MAIN is only set in that child, so we start there).
    if not is_debug or os.environ.get("WERKZEUG_RUN_MAIN") == "true":
        start_scheduler(app)
    # host=0.0.0.0 so other devices on your LAN can access the tracking links.
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "5000")), debug=is_debug)
