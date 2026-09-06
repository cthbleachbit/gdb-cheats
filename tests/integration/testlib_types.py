import base64
import json
import traceback
from dataclasses import dataclass
from enum import Enum
from typing import Any, List, Dict, Union, Optional, Self


class MessageClass(str, Enum):
    """
    Represents the different types of messages that can be sent from the in-debugger agent.

    - INFO
      Informational.
    - TEST_ERROR
      Error in the test payload.
    - HARNESS_ERROR
      Error in the harness / agent itself.
    """
    INFO = "info"
    TEST_ERROR = "test_error"
    HARNESS_ERROR = "harness_error"

    def is_error(self) -> bool:
        return self == MessageClass.TEST_ERROR or self == MessageClass.HARNESS_ERROR


type MessageDetail = Union[Dict, List, str]


@dataclass
class AgentMessage:
    class_: MessageClass
    type_: str
    details: Optional[MessageDetail] = None

    def is_error(self) -> bool:
        return self.class_.is_error()

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AgentMessage":
        try:
            msg_class = MessageClass(data["class"])
            msg_class_enum = MessageClass(msg_class)
        except KeyError:
            raise ValueError("Missing `class` keyword")
        except ValueError:
            raise ValueError(f"Invalid `class` value: {data['class']}")

        try:
            msg_type = data["type"]
        except KeyError:
            raise ValueError("Missing `type` keyword")

        msg_payload = data.get("payload", None)
        if msg_payload is not None and not isinstance(msg_payload, (dict, list, str)):
            raise ValueError("`payload` must be a dict or list")

        return cls(
            class_=msg_class_enum,
            type_=msg_type,
            details=msg_payload,
        )

    def as_dict(self) -> Dict:
        ret: Dict[str, Any] = {
            "class": self.class_.value,
            "type": self.type_
        }

        if self.details is not None:
            ret["payload"] = self.details
        return ret

    @classmethod
    def info(cls, type_: str, details: Optional[MessageDetail] = None) -> Self:
        return cls(class_=MessageClass.INFO, type_=type_, details=details)

    @classmethod
    def test_error(cls, type_: str, details: Optional[MessageDetail] = None) -> Self:
        return cls(class_=MessageClass.TEST_ERROR, type_=type_, details=details)

    @classmethod
    def test_exception(cls, exception: Exception, type_: Optional[str] = None) -> Self:
        return cls(class_=MessageClass.TEST_ERROR, type_=type_ or "exception_in_payload",
                   details=traceback.format_exception(exception))

    @classmethod
    def harness_error(cls, type_: str, details: Optional[MessageDetail] = None) -> Self:
        return cls(class_=MessageClass.HARNESS_ERROR, type_=type_, details=details)

    @classmethod
    def harness_exception(cls, exception: Exception, type_: Optional[str] = None) -> Self:
        return cls(class_=MessageClass.HARNESS_ERROR, type_=type_ or "exception_in_agent",
                   details=traceback.format_exception(exception))


def base64_enc(obj: Any) -> str:
    return base64.b64encode(json.dumps(obj).encode("utf-8")).decode("utf-8")


def base64_dec(encoded: str) -> Any:
    return json.loads(base64.b64decode(encoded).decode("utf-8"))


class EnvConstants:
    # Writable path for agent to output status
    IPC_FILE_PATH = "TEST_IPC_FIFO"
    # Actual test script
    PAYLOAD_SCRIPT_PATH = "TEST_SCRIPT"
    # The function to run upon breakpoint
    PAYLOAD_FUNCTION_NAME = "TEST_FUNCTION"
    # Breakpoints to set (base64 encoded list of strings)
    BREAKPOINTS = "TEST_BREAKPOINTS"
