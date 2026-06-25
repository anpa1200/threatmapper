"""
Integration test bootstrap.

Ensures the log directory is writable when running tests outside of Docker
(where the default `logs/` directory may be owned by root).
"""

import os

# Redirect logs to /tmp so the logging handler can always write, regardless of
# whether the Docker-created `logs/` directory is accessible to the current user.
os.environ.setdefault("LOG_DIR", "/tmp/adversarygraph-test-logs")
