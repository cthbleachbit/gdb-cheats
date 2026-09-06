"""
In-debugger agent for textlibexec_load_and_run_test.py
"""
import base64
import importlib
import importlib.util
import json
import os
import sys
import traceback
from pathlib import Path
from typing import Dict, Optional, NoReturn, Callable

ENV_IPC_FIFO_PATH = os.environ.get("TEST_IPC_FIFO", "")
ENV_PAYLOAD_SCRIPT = os.environ.get("TEST_SCRIPT", "")
ENV_PAYLOAD_FUNC = os.environ.get("TEST_FUNCTION", "")

PAYLOAD_FUNC: Callable


def get_gdb_module():
    try:
        return importlib.import_module("gdb")
    except ImportError:
        return None


def send_message(message: Dict):
    try:
        with open(ENV_IPC_FIFO_PATH, "a") as out_file:
            out_file.write(base64.b64encode(json.dumps(message).encode()).decode() + "\n")
            out_file.flush()
    except Exception as e:
        traceback.print_exception(e)
    finally:
        pass


def agent_main():
    # In-debugger agent.
    # Payload location should be set.
    if not ENV_PAYLOAD_SCRIPT or not ENV_PAYLOAD_FUNC:
        agent_bail({"type": "payload_var_unspec", "class": "invalid_input"})

    # Check if the test payload exists and can be imported.
    # Inject the directory containing the test payload into the sys search path.
    script_path = Path(ENV_PAYLOAD_SCRIPT).resolve()
    integration_test_dir = script_path.parent
    if str(integration_test_dir) not in sys.path:
        sys.path.insert(0, str(integration_test_dir))

    # Load the fixture.
    try:
        testlib_fixtures = importlib.import_module("testlib_fixtures")
    except ImportError as e:
        agent_bail(
            {"type": "fixture_import_fail", "class": "invalid_input", "traceback": traceback.format_exception(e)})

    send_message({"type": "fixture_loaded", "class": "info", "file": str(testlib_fixtures.__file__)})

    test_payload_spec = importlib.util.spec_from_file_location(
        script_path.stem,
        ENV_PAYLOAD_SCRIPT,
        submodule_search_locations=[str(integration_test_dir)]
    )
    if test_payload_spec is None or test_payload_spec.loader is None:
        agent_bail({"type": "payload_spec_creation_fail", "class": "invalid_input"})
    try:
        test_payload_module = importlib.util.module_from_spec(test_payload_spec)
        sys.modules[script_path.stem] = test_payload_module
        test_payload_spec.loader.exec_module(test_payload_module)
    except Exception as e:
        agent_bail(
            {"type": "payload_load_exception", "class": "invalid_input", "traceback": traceback.format_exception(e)})

    send_message({"type": "payload_file_loaded", "class": "info", "file": test_payload_module.__file__})

    if not hasattr(test_payload_module, ENV_PAYLOAD_FUNC):
        agent_bail({"type": "payload_func_not_found", "class": "invalid_input", "func": ENV_PAYLOAD_FUNC})

    payload_function = getattr(test_payload_module, ENV_PAYLOAD_FUNC)

    global PAYLOAD_FUNC
    PAYLOAD_FUNC = payload_function
    send_message({"type": "payload_func_loaded", "class": "info"})


def run_payload():
    gdb = get_gdb_module()
    gdb_cheats = importlib.import_module("gdb_cheats")
    setattr(gdb_cheats, "core", importlib.import_module("gdb_cheats.core"))
    setattr(gdb_cheats, "search", importlib.import_module("gdb_cheats.search"))
    try:
        PAYLOAD_FUNC(gdb_cheats, gdb)
    except Exception as e:
        agent_bail({"type": "payload_run_exception", "class": "test_error", "traceback": traceback.format_exception(e)})

    send_message({"type": "payload_run_complete", "class": "info"})


def agent_bail(death_message: Optional[Dict] = None) -> NoReturn:
    if death_message is not None:
        send_message(death_message)

    raise SystemExit(255)


def main():
    # Are we in gdb?
    gdb = get_gdb_module()
    if gdb is None:
        # We are being inspected by the outside driver. Do nothing.
        return

    if ENV_IPC_FIFO_PATH == "":
        # No fifo specified. Bail.
        agent_bail()

    # Open the fifo
    try:
        fifo = open(ENV_IPC_FIFO_PATH, "w")
        fifo.close()
    except OSError:
        agent_bail()

    # At this point we can send message.
    send_message(
        {"type": "initialized", "class": "info"}
    )

    try:
        agent_main()
    except Exception as e:
        agent_bail({"type": "agent_main_exception", "class": "unspecified", "traceback": traceback.format_exception(e)})


if __name__ == "__main__":
    main()
