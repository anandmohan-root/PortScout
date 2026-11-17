import os
import tempfile

# Keep test history out of the real %LOCALAPPDATA%\PortScout.
os.environ["LOCALAPPDATA"] = tempfile.mkdtemp(prefix="portscout-test-")
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
