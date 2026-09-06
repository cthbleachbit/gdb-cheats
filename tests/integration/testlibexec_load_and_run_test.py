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
from typing import Optional, NoReturn, Callable

from tests.integration.testlib_types import AgentMessage

ENV_IPC_FIFO_PATH = os.environ.get("TEST_IPC_FIFO", "")
ENV_PAYLOAD_SCRIPT = os.environ.get("TEST_SCRIPT", "")
ENV_PAYLOAD_FUNC = os.environ.get("TEST_FUNCTION", "")

PAYLOAD_FUNC: Callable


def get_gdb_module():
    try:
        return importlib.import_module("gdb")
    except ImportError:
        return None


def send_message(message: AgentMessage):
    try:
        with open(ENV_IPC_FIFO_PATH, "a") as out_file:
            out_file.write(base64.b64encode(json.dumps(message.as_dict()).encode()).decode() + "\n")
            out_file.flush()
    except Exception as e:
        traceback.print_exception(e)
    finally:
        pass


def exit_with_message(death_message: Optional[AgentMessage] = None) -> NoReturn:
    if death_message is not None:
        send_message(death_message)

    raise SystemExit(255)


def agent_main():
    # In-debugger agent.
    # Payload location should be set.
    if not ENV_PAYLOAD_SCRIPT or not ENV_PAYLOAD_FUNC:
        exit_with_message(AgentMessage.harness_error(type_="payload_var_unspec"))

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
        exit_with_message(AgentMessage.harness_exception(exception=e, type_="fixture_import_fail"))

    send_message(AgentMessage.info("fixture_loaded", {"file": str(testlib_fixtures.__file__)}))

    test_payload_spec = importlib.util.spec_from_file_location(
        script_path.stem,
        ENV_PAYLOAD_SCRIPT,
        submodule_search_locations=[str(integration_test_dir)]
    )
    if test_payload_spec is None or test_payload_spec.loader is None:
        exit_with_message(AgentMessage.harness_error(type_="payload_spec_creation_fail"))
    try:
        test_payload_module = importlib.util.module_from_spec(test_payload_spec)
        sys.modules[script_path.stem] = test_payload_module
        test_payload_spec.loader.exec_module(test_payload_module)
    except Exception as e:
        exit_with_message(AgentMessage.harness_exception(exception=e, type_="payload_load_exception"))

    send_message(AgentMessage.info("payload_file_loaded", {"file": str(test_payload_module.__file__)}))

    if not hasattr(test_payload_module, ENV_PAYLOAD_FUNC):
        exit_with_message(AgentMessage.harness_error("payload_func_not_found",
                                                     {"file": str(testlib_fixtures.__file__),
                                                      "func": ENV_PAYLOAD_FUNC}))

    payload_function = getattr(test_payload_module, ENV_PAYLOAD_FUNC)

    global PAYLOAD_FUNC
    PAYLOAD_FUNC = payload_function
    send_message(AgentMessage.info("payload_func_loaded"))


def run_payload():
    gdb = get_gdb_module()
    gdb_cheats = importlib.import_module("gdb_cheats")
    setattr(gdb_cheats, "core", importlib.import_module("gdb_cheats.core"))
    setattr(gdb_cheats, "search", importlib.import_module("gdb_cheats.search"))
    try:
        PAYLOAD_FUNC(gdb_cheats, gdb)
    except Exception as e:
        exit_with_message(AgentMessage.test_exception(e, "payload_run_exception"))

    send_message(AgentMessage.info("payload_run_complete"))


def main():
    # Are we in gdb?
    gdb = get_gdb_module()
    if gdb is None:
        # We are being inspected by the outside driver. Do nothing.
        return

    if ENV_IPC_FIFO_PATH == "":
        # No fifo specified. Bail.
        exit_with_message()

    # Open the fifo
    try:
        fifo = open(ENV_IPC_FIFO_PATH, "w")
        fifo.close()
    except OSError:
        exit_with_message()

    # At this point we can send message.
    send_message(AgentMessage.info("initialized"))

    try:
        agent_main()
    except Exception as e:
        exit_with_message(AgentMessage.harness_exception(e, "unhandled_exception"))


if __name__ == "__main__":
    main()
