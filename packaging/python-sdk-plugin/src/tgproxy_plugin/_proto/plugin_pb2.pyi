from google.protobuf.internal import containers as _containers
from google.protobuf.internal import enum_type_wrapper as _enum_type_wrapper
from google.protobuf import descriptor as _descriptor
from google.protobuf import message as _message
from typing import ClassVar as _ClassVar, Iterable as _Iterable, Mapping as _Mapping, Optional as _Optional, Union as _Union

DESCRIPTOR: _descriptor.FileDescriptor

class Direction(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    DIRECTION_REQUEST: _ClassVar[Direction]
    DIRECTION_RESPONSE: _ClassVar[Direction]

class Severity(int, metaclass=_enum_type_wrapper.EnumTypeWrapper):
    __slots__ = ()
    SEVERITY_INFO: _ClassVar[Severity]
    SEVERITY_LOW: _ClassVar[Severity]
    SEVERITY_MEDIUM: _ClassVar[Severity]
    SEVERITY_HIGH: _ClassVar[Severity]
    SEVERITY_CRITICAL: _ClassVar[Severity]
DIRECTION_REQUEST: Direction
DIRECTION_RESPONSE: Direction
SEVERITY_INFO: Severity
SEVERITY_LOW: Severity
SEVERITY_MEDIUM: Severity
SEVERITY_HIGH: Severity
SEVERITY_CRITICAL: Severity

class Empty(_message.Message):
    __slots__ = ()
    def __init__(self) -> None: ...

class PluginInfo(_message.Message):
    __slots__ = ("name", "version")
    NAME_FIELD_NUMBER: _ClassVar[int]
    VERSION_FIELD_NUMBER: _ClassVar[int]
    name: str
    version: str
    def __init__(self, name: _Optional[str] = ..., version: _Optional[str] = ...) -> None: ...

class Hints(_message.Message):
    __slots__ = ("content_type", "url", "method", "direction")
    CONTENT_TYPE_FIELD_NUMBER: _ClassVar[int]
    URL_FIELD_NUMBER: _ClassVar[int]
    METHOD_FIELD_NUMBER: _ClassVar[int]
    DIRECTION_FIELD_NUMBER: _ClassVar[int]
    content_type: str
    url: str
    method: str
    direction: Direction
    def __init__(self, content_type: _Optional[str] = ..., url: _Optional[str] = ..., method: _Optional[str] = ..., direction: _Optional[_Union[Direction, str]] = ...) -> None: ...

class Finding(_message.Message):
    __slots__ = ("type", "severity", "start", "end", "confidence", "scanner", "metadata")
    class MetadataEntry(_message.Message):
        __slots__ = ("key", "value")
        KEY_FIELD_NUMBER: _ClassVar[int]
        VALUE_FIELD_NUMBER: _ClassVar[int]
        key: str
        value: str
        def __init__(self, key: _Optional[str] = ..., value: _Optional[str] = ...) -> None: ...
    TYPE_FIELD_NUMBER: _ClassVar[int]
    SEVERITY_FIELD_NUMBER: _ClassVar[int]
    START_FIELD_NUMBER: _ClassVar[int]
    END_FIELD_NUMBER: _ClassVar[int]
    CONFIDENCE_FIELD_NUMBER: _ClassVar[int]
    SCANNER_FIELD_NUMBER: _ClassVar[int]
    METADATA_FIELD_NUMBER: _ClassVar[int]
    type: str
    severity: Severity
    start: int
    end: int
    confidence: float
    scanner: str
    metadata: _containers.ScalarMap[str, str]
    def __init__(self, type: _Optional[str] = ..., severity: _Optional[_Union[Severity, str]] = ..., start: _Optional[int] = ..., end: _Optional[int] = ..., confidence: _Optional[float] = ..., scanner: _Optional[str] = ..., metadata: _Optional[_Mapping[str, str]] = ...) -> None: ...

class ScanRequest(_message.Message):
    __slots__ = ("data", "hints")
    DATA_FIELD_NUMBER: _ClassVar[int]
    HINTS_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    hints: Hints
    def __init__(self, data: _Optional[bytes] = ..., hints: _Optional[_Union[Hints, _Mapping]] = ...) -> None: ...

class ScanResponse(_message.Message):
    __slots__ = ("findings",)
    FINDINGS_FIELD_NUMBER: _ClassVar[int]
    findings: _containers.RepeatedCompositeFieldContainer[Finding]
    def __init__(self, findings: _Optional[_Iterable[_Union[Finding, _Mapping]]] = ...) -> None: ...

class RedactRequest(_message.Message):
    __slots__ = ("data", "findings")
    DATA_FIELD_NUMBER: _ClassVar[int]
    FINDINGS_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    findings: _containers.RepeatedCompositeFieldContainer[Finding]
    def __init__(self, data: _Optional[bytes] = ..., findings: _Optional[_Iterable[_Union[Finding, _Mapping]]] = ...) -> None: ...

class RedactResponse(_message.Message):
    __slots__ = ("data",)
    DATA_FIELD_NUMBER: _ClassVar[int]
    data: bytes
    def __init__(self, data: _Optional[bytes] = ...) -> None: ...
