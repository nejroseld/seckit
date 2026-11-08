"""Keep the encrypted-file fallback of the secret store out of the real home directory."""
import atexit
import os
import shutil
import tempfile

if "SECKIT_HOME" not in os.environ:
    _home = tempfile.mkdtemp(prefix="seckit-test-home-")
    os.environ["SECKIT_HOME"] = _home
    atexit.register(shutil.rmtree, _home, True)

# Trust records (which .seckit files the user accepted) never go to the real user cache.
import seckit.trust as _trust_module  # noqa: E402
from pathlib import Path as _Path  # noqa: E402

_trust_dir = tempfile.mkdtemp(prefix="seckit-test-trust-")
atexit.register(shutil.rmtree, _trust_dir, True)
_trust_module._record_path = lambda: _Path(_trust_dir) / "trust.json"

# Unit tests mock subprocess.run; never probe user namespaces under a mock. Tests of the
# namespace path set seckit.sandbox._ISOLATION themselves.
import seckit.sandbox as _sandbox_module  # noqa: E402

_sandbox_module._ISOLATION = []
