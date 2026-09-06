"""
In-debugger setup.

To be sourced from the debugger driver.
"""
import base64
import json
import os
import sys

if __name__ == "__main__":
    # Replace `sys.path` with the path to the debugger driver's parent directory
    test_sys_path: str = os.environ.get("TEST_SYS_PATH", "")
    if not test_sys_path:
        sys.exit(5)

    sys.path = json.loads(base64.b64decode(test_sys_path.encode()))
