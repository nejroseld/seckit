"""Keep the encrypted-file fallback of the secret store out of the real home directory."""
import atexit
import os
import shutil
import tempfile

if "BLUEKIT_HOME" not in os.environ:
    _home = tempfile.mkdtemp(prefix="bluekit-test-home-")
    os.environ["BLUEKIT_HOME"] = _home
    atexit.register(shutil.rmtree, _home, True)
