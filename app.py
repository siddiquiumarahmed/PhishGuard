"""Local entry point.

    flask --app app run            (recommended; add --debug while developing)
    python app.py                  (equivalent, binds to 127.0.0.1:5000)

The server binds to the loopback interface only. PhishGuard is a local tool;
see README.md before exposing it to other machines.
"""

import os

from phishguard import create_app

app = create_app()

if __name__ == "__main__":
    port = int(os.environ.get("PHISHGUARD_PORT", "5000"))
    app.run(host="127.0.0.1", port=port, debug=False)
