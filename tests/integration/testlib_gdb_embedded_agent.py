"""
In-debugger agent for textlibexec_load_and_run_test.py

Execution flow:
- `python agent_init()` - sets up IPC and payload, sets up breakpoints.
- `python agent_setup()` - loads testing script and sets up breakpoints.
- `run` starts instrumentation.
  Any breakpoints requested by the test will run the test function.
  The test function returning False/None will pass the test.

"""
import base64
import functools
import importlib
import importlib.util
import json
import os
import sys
import traceback
from pathlib import Path
from typing import Optional, NoReturn, Callable, List, Dict

from tests.integration.testlib_types import AgentMessage, EnvConstants, base64_dec

ENV_IPC_FIFO_PATH = os.environ.get(EnvConstants.IPC_FILE_PATH, "")
ENV_PAYLOAD_SCRIPT = os.environ.get(EnvConstants.PAYLOAD_SCRIPT_PATH, "")
ENV_PAYLOAD_FUNC = os.environ.get(EnvConstants.PAYLOAD_FUNCTION_NAME, "")
ENV_BREAKPOINTS = os.environ.get(EnvConstants.BREAKPOINTS, "")

# The wrapped test function.
PAYLOAD_FUNC: Callable
# Breakpoints requested by the test.
BREAKPOINT_SPECS: List[str]
# Actual breakpoint instances of gdb.Breakpoint
BREAKPOINT_INSTANCES: List[object] = []
# USer context - scratch space for notetaking in the test function.
CONTEXT: Dict = dict()


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


def agent_exit_with_message(death_message: Optional[AgentMessage] = None) -> NoReturn:
    if death_message is not None:
        send_message(death_message)

    raise SystemExit(255)


def agent_pass() -> NoReturn:
    gdb = get_gdb_module()
    assert gdb

    send_message(AgentMessage.info("payload_run_complete"))
    gdb.execute("quit")
    # Should not be here
    raise SystemExit(0)


def exit_on_exception(func):
    def _wrapped(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            agent_exit_with_message(AgentMessage.harness_exception(e))

    return _wrapped


@exit_on_exception
def agent_setup():
    global BREAKPOINT_SPECS
    global BREAKPOINT_INSTANCES
    global PAYLOAD_FUNC

    gdb = get_gdb_module()
    assert gdb

    # Payload location should be set.
    if not ENV_PAYLOAD_SCRIPT or not ENV_PAYLOAD_FUNC:
        agent_exit_with_message(AgentMessage.harness_error(type_="payload_var_unspec"))

    # Check if the test payload exists and can be imported.
    # Inject the directory containing the test payload into the sys search path.
    script_path = Path(ENV_PAYLOAD_SCRIPT).resolve()
    integration_test_dir = script_path.parent
    if str(integration_test_dir) not in sys.path:
        sys.path.insert(0, str(integration_test_dir))

    # Parse breakpoints
    if not ENV_BREAKPOINTS:
        agent_exit_with_message(AgentMessage.harness_error(type_="breakpoints_var_unspec"))
    BREAKPOINT_SPECS = base64_dec(ENV_BREAKPOINTS)

    # Load the fixture.
    try:
        testlib_fixtures = importlib.import_module("testlib_fixtures")
    except ImportError as e:
        agent_exit_with_message(AgentMessage.harness_exception(exception=e, type_="fixture_import_fail"))

    send_message(AgentMessage.info("fixture_loaded", {"file": str(testlib_fixtures.__file__)}))

    test_payload_spec = importlib.util.spec_from_file_location(
        script_path.stem,
        ENV_PAYLOAD_SCRIPT,
        submodule_search_locations=[str(integration_test_dir)]
    )
    if test_payload_spec is None or test_payload_spec.loader is None:
        agent_exit_with_message(AgentMessage.harness_error(type_="payload_spec_creation_fail"))
    try:
        test_payload_module = importlib.util.module_from_spec(test_payload_spec)
        sys.modules[script_path.stem] = test_payload_module
        test_payload_spec.loader.exec_module(test_payload_module)
    except Exception as e:
        agent_exit_with_message(AgentMessage.harness_exception(exception=e, type_="payload_load_exception"))

    send_message(AgentMessage.info("payload_file_loaded", {"file": str(test_payload_module.__file__)}))

    if not hasattr(test_payload_module, ENV_PAYLOAD_FUNC):
        agent_exit_with_message(AgentMessage.harness_error("payload_func_not_found",
                                                           {"file": str(testlib_fixtures.__file__),
                                                            "func": ENV_PAYLOAD_FUNC}))

    PAYLOAD_FUNC = getattr(test_payload_module, ENV_PAYLOAD_FUNC)
    send_message(AgentMessage.info("payload_func_loaded"))

    # ==================================================================
    # All information has been gathered.
    # Sets up breakpoints.

    in_debugger_types = importlib.import_module("tests.integration.testlib_gdb_types")

    for breakpoint_spec in BREAKPOINT_SPECS:
        try:
            breakpoint_ = in_debugger_types.AgentTestBreakpoint(breakpoint_spec,
                                                                functools.partial(agent_on_breakpoint, breakpoint_spec))
            BREAKPOINT_INSTANCES.append(breakpoint_)
            send_message(AgentMessage.info("breakpoint_installed", {"breakpoint": breakpoint_spec}))
        except gdb.error as e:
            agent_exit_with_message(
                AgentMessage.harness_error("breakpoint_setup_failed", {"breakpoint": breakpoint_spec, "error": str(e)}))

    send_message(AgentMessage.info("setup_complete"))


def agent_on_breakpoint(breakpoint_spec: str, breakpoint_: object):
    """
    Invoked when the agent hits a breakpoint.
    Driven by `AgentTestBreakpoint.stop`.
    """
    global CONTEXT
    gdb = get_gdb_module()
    gdb_cheats = importlib.import_module("gdb_cheats")

    assert gdb is not None and gdb_cheats is not None

    setattr(gdb_cheats, "core", importlib.import_module("gdb_cheats.core"))
    setattr(gdb_cheats, "search", importlib.import_module("gdb_cheats.search"))

    send_message(AgentMessage.info("payload_breakpoint_eval_start", {"breakpoint_spec": breakpoint_spec}))
    try:
        bp_eval_continue = bool(PAYLOAD_FUNC(gdb_cheats, gdb, CONTEXT, bp=(breakpoint_spec, breakpoint_)))
    except Exception as e:
        agent_exit_with_message(AgentMessage.test_exception(e, "payload_breakpoint_eval_exception"))
    send_message(AgentMessage.info("payload_breakpoint_eval_complete", {"breakpoint_spec": breakpoint_spec}))

    if bp_eval_continue:
        # Not explicitly `continue` here as the breakpoint subclass will do that.
        # See `AgentTestBreakpoint`.
        return
    else:
        agent_pass()


@exit_on_exception
def agent_init():
    # Are we in gdb?
    gdb = get_gdb_module()
    if gdb is None:
        # We are being inspected by the outside driver. Do nothing.
        return

    if ENV_IPC_FIFO_PATH == "":
        # No fifo specified. Bail.
        agent_exit_with_message()

    # Open the fifo
    try:
        fifo = open(ENV_IPC_FIFO_PATH, "w")
        fifo.close()
    except OSError:
        agent_exit_with_message()

    # At this point we can send messages.
    send_message(AgentMessage.info("initialized"))
