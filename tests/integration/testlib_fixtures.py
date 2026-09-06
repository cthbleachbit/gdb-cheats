import base64
import inspect
import json
import os
import pprint
import subprocess
import sys
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Optional, List, Dict, Union

import pytest

from gdb_cheats.assembly.programs import *
from tests.integration import testlibexec_load_and_run_test as embedded_driver
from tests.integration.testlib_types import AgentMessage


def get_gdb():
    return get_program("gdb", "GDB", True)


def require_programs():
    try:
        get_gnu_assembler(True)
        get_objdump(True)
        get_objcopy(True)

        get_gdb()
    except EnvironmentError as e:
        pytest.xfail(f"Missing programs {str(e)}")


def execute_in_gdb(inferior: str,
                   breakpoint_spec: str,
                   timeout_sec=10,
                   inferior_path: Union[str, Path] = "",
                   inferior_args: Optional[List[str]] = None,
                   inferior_env: Optional[Dict[str, str]] = None):
    """
    Run the given function in the cheat engine with GDB attached to the given program stopped at the given breakpoint.

    The wrapped test function will be reimported and executed inside GDB with a test agent.
    The test agent accessing the test payload will have to skip this decorator and run the naked function instead,
    so this decorator becomes no-op when the `gdb` module is available (in other words inside GDB).

    The wrapped test function should accept two arguments: `gdb_cheats` and `gdb`. The test agent exposes the
    `gdb_cheats` and `gdb` modules as arguments to the test function. Test scripts thus should not import `gdb_cheats`
    nor `gdb` modules at the top.

    :param inferior: The inferior program to run.
    :param breakpoint_spec: When to stop the inferior program.
    :param timeout_sec: How long to wait for the debugger to quit.
    :param inferior_path: The directory containing the inferior program.
    :param inferior_args: Arguments to pass to the inferior program.
    :param inferior_env: Environment variables to pass to the debugger.
    """
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

    # check if inferior is a file
    if not inferior.is_file(follow_symlinks=True):
        pytest.xfail(f"Missing inferior program {inferior}")

    # Resolve the in-debugger driver
    if embedded_driver.__file__ is None:
        pytest.xfail(f"Could not inspect debugger driver `textlibexec_load_and_run_test`")

    debugger_driver_path = Path(embedded_driver.__file__).resolve()

    def decorator_inner(func):
        # Resolve the function and the file it is in.
        test_file = inspect.getsourcefile(func)
        symbol_name = func.__name__

        def _run_in_gdb():
            with NamedTemporaryFile("r", prefix="cheats-gdb-test-", delete=False) as tmp_out:
                # Expect the python inside will send us updates to the fifo
                # One line per message. Each message should be one serialized JSON dictionary encoded with base64.

                real_inferior_env["TEST_IPC_FIFO"] = str(tmp_out.name)
                real_inferior_env["TEST_SCRIPT"] = str(test_file)
                real_inferior_env["TEST_FUNCTION"] = symbol_name

                gdb_command_line = [
                    "cheats-gdb",
                    # Unattended mode
                    "-iex", "set pagination off",
                    "-iex", "set confirm off",
                    # Load agent
                    "-iex", f"source {str(debugger_driver_path)}",
                    # Sets breakpoint
                    "-ex", f"break {breakpoint_spec}",
                    "-ex", f"run",
                    # Run payload
                    "-ex", "python run_payload()",
                    "--args", str(inferior), *real_inferior_args
                ]

                gdb_proc = subprocess.Popen(gdb_command_line, env=real_inferior_env,
                                            stdin=subprocess.DEVNULL, stderr=subprocess.PIPE, stdout=subprocess.PIPE,
                                            text=True)

                test_errors: List[str] = []

                try:
                    gdb_proc.wait(timeout_sec)
                except subprocess.TimeoutExpired as e:
                    gdb_proc.kill()
                    test_errors.append(str(e))

                # At this point gdb should have exited.
                assert gdb_proc.returncode is not None

                # Grab output
                stdout, stderr = gdb_proc.communicate()
                if gdb_proc.returncode != 0:
                    test_errors.append(
                        f"GDB exited with non-zero {gdb_proc.returncode}.\nSTDOUT:\n{stdout}\nSTDERR:\n{stderr}")

                serialized_messages: List[AgentMessage] = [AgentMessage.from_dict(json.loads(base64.b64decode(line)))
                                                           for line in tmp_out.readlines()]

                # Expect to see "initialized" and "payload_loaded" messages.
                if not any(message.type_ == "initialized" for message in serialized_messages):
                    test_errors.append("Missing `initialized` message - this run is probably invalid.")
                if not any(message.type_ == "payload_run_complete" for message in serialized_messages):
                    test_errors.append("Missing `payload payload_run_complete` message. Run failed.")

                # Any other messages should be failures.
                failure_messages = [failure for failure in serialized_messages if failure.is_error()]
                if failure_messages:
                    for message in serialized_messages:
                        test_errors.append(f"Test agent report:\n{pprint.pformat(message.as_dict())}")

                if test_errors:
                    pytest.fail(f"Test failed. Errors: \n{'\n\n'.join(test_errors)}")

                # Print the messages to stderr for reference
                for message in serialized_messages:
                    print(f"Test agent report:\n{pprint.pformat(message.as_dict())}", file=sys.stderr)

        return _run_in_gdb

    return decorator_inner
