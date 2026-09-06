"""
Integration test fixture supporting evaluating test functions on a live inferior.
"""

import inspect
import os
import pprint
import subprocess
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Optional, List, Dict, Union

import pytest

from gdb_cheats.assembly.programs import *
from tests.integration import testlib_gdb_embedded_agent as embedded_driver
from tests.integration.testlib_types import AgentMessage, base64_enc, base64_dec, EnvConstants


def get_gdb():
    return get_program("gdb", "GDB", True)


def require_programs():
    try:
        get_gnu_assembler(True)
        get_objdump(True)
        get_objcopy(True)

        get_gdb()
    except EnvironmentError as e:
        pytest.skip(f"Missing required programs {str(e)}")


def execute_in_gdb(inferior: str,
                   breakpoint_spec: Union[str, List[str]],
                   timeout_sec=10,
                   inferior_path: Union[str, Path] = "",
                   inferior_args: Optional[List[str]] = None,
                   inferior_env: Optional[Dict[str, str]] = None):
    """
    Decorator driving the decorated function in GDB attached to the given program stopped at given breakpoints.

    The provided function will be invoked inside GDB every time the inferior program stops at each of the given
    breakpoints.
    The wrapped test function should have the following signature:
    - Positional argument `gdb_cheats`: cheat engine module exposed by the test agent.
    - Positional argument `gdb`: GDB module exposed by the test agent.
    - Positional argument `context`: Provided dictionary for test function to track states.
    - Optional keyword argument `bp`: tuple of spec and gdb breakpoint object.
    The wrapped test function should return...
    - `False` or `None` upon successful completion of the test to quit the debugger.
    - `True` to continue debugging.

    Test scripts thus should not import `gdb_cheats` nor `gdb` modules at the top.

    :param inferior: The inferior program to run.
    :param breakpoint_spec: When to stop the inferior program.
    :param timeout_sec: How long to wait for the debugger to quit.
    :param inferior_path: The directory containing the inferior program.
    :param inferior_args: Arguments to pass to the inferior program.
    :param inferior_env: Environment variables to pass to the debugger.
    """

    # The test agent accessing the test payload will have to skip this decorator and run the naked function instead.
    # This decorator must skip modifying the function when inside GDB.
    if "gdb" in sys.modules.keys():
        # We are being loaded from inside GDB. Make this decorator a no-op.
        def _no_op_decorator(func):
            return func

        return _no_op_decorator

    require_programs()

    # Normalize arguments
    if inferior_env is None:
        real_inferior_env = os.environ
    else:
        real_inferior_env = dict(os.environ)
        real_inferior_env.update(inferior_env)
    real_inferior_args: List[str] = [] if inferior_args is None else inferior_args
    inferior = Path(inferior_path) / inferior

    if isinstance(breakpoint_spec, str):
        encoded_breakpoint_spec = base64_enc([breakpoint_spec])
    elif isinstance(breakpoint_spec, list):
        encoded_breakpoint_spec = base64_enc(breakpoint_spec)
    else:
        raise TypeError(f"Invalid breakpoint_spec type: {type(breakpoint_spec)}")
    real_inferior_env[EnvConstants.BREAKPOINTS] = encoded_breakpoint_spec

    # check if inferior is a file
    if not inferior.is_file(follow_symlinks=True):
        pytest.xfail(f"Missing inferior program {inferior}")

    # Resolve the in-debugger driver
    if embedded_driver.__file__ is None:
        pytest.xfail(f"Could not inspect debugger driver `testlib_gdb_embedded_agent`")

    debugger_driver_path = Path(embedded_driver.__file__).resolve()

    def decorator_inner(func):
        # Resolve the function and the file it is in.
        test_file = inspect.getsourcefile(func)
        symbol_name = func.__name__

        def _run_in_gdb():
            with NamedTemporaryFile("r", prefix="cheats-gdb-test-", delete=False) as tmp_out:
                # Expect the python inside will send us updates to the fifo
                # One line per message. Each message should be one serialized JSON dictionary encoded with base64.

                real_inferior_env[EnvConstants.IPC_FILE_PATH] = str(tmp_out.name)
                real_inferior_env[EnvConstants.PAYLOAD_SCRIPT_PATH] = str(test_file)
                real_inferior_env[EnvConstants.PAYLOAD_FUNCTION_NAME] = symbol_name

                gdb_command_line = [
                    "cheats-gdb",
                    # Unattended mode
                    "-iex", "set pagination off",
                    "-iex", "set confirm off",
                    # Load agent
                    "-iex", f"source {str(debugger_driver_path)}",
                    # Sets breakpoint
                    "-ex", f"python agent_init()",
                    "-ex", f"python agent_setup()",
                    "-ex", f"run",
                    # Catch all exit - should not be here.
                    "-ex", "python raise SystemExit(1)",
                    "--args", str(inferior), *real_inferior_args
                ]

                gdb_proc = subprocess.Popen(gdb_command_line, env=real_inferior_env,
                                            stdin=subprocess.DEVNULL, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                            text=True)

                # Cumulative list of errors.
                test_errors: List[str] = []

                try:
                    gdb_proc.wait(timeout_sec)
                except subprocess.TimeoutExpired as e:
                    gdb_proc.kill()
                    test_errors.append(str(e))

                # At this point gdb should have exited.
                gdb_proc.wait()
                assert gdb_proc.returncode is not None

                # Grab output
                stdout, stderr = gdb_proc.communicate()
                if gdb_proc.returncode != 0:
                    test_errors.append(
                        f"GDB exited with non-zero {gdb_proc.returncode}.\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}")

                serialized_messages = [AgentMessage.from_dict(base64_dec(line)) for line in tmp_out.readlines()]

                # Expect to see "initialized" and "payload_loaded" messages.
                if not any(message.type_ == "initialized" for message in serialized_messages):
                    test_errors.append("Missing `initialized` message - this run is probably invalid.")
                if not any(message.type_ == "setup_complete" for message in serialized_messages):
                    test_errors.append("Missing `setup_complete` message - this run is probably invalid.")
                if not any(message.type_ == "payload_run_complete" for message in serialized_messages):
                    test_errors.append("Missing `payload payload_run_complete` message. Run failed.")

                # Any other messages should be failures.
                failure_messages = [failure for failure in serialized_messages if failure.is_error()]
                if failure_messages:
                    for message in serialized_messages:
                        test_errors.append(f"Test agent reported errors")

                # Print the messages to stderr for reference
                for message in serialized_messages:
                    print(f"{pprint.pformat(message.as_dict())}\n", file=sys.stderr)

                if test_errors:
                    pytest.fail(f"Test failed. Errors: \n{'\n\n'.join(test_errors)}")

        return _run_in_gdb

    return decorator_inner
