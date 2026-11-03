"""Keep the encrypted-file fallback of the secret store out of the real home directory."""
import atexit
import os
import shutil
import tempfile

if "SECKIT_HOME" not in os.environ:
    _home = tempfile.mkdtemp(prefix="seckit-test-home-")
    os.environ["SECKIT_HOME"] = _home
    atexit.register(shutil.rmtree, _home, True)
