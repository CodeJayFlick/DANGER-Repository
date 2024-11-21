Here is the translation of the given Java code into equivalent Python:

```Python
import enum
from typing import Optional

class ErrorCode(enum.Enum):
    UNKNOWN = 1


def ex(error_code: ErrorCode) -> Optional[Exception]:
    error = {'reason': 'test', 'status': 1, 'error_code': error_code}
    return Exception(f"NessieError {error}")


def test_unknown():
    assert not ex(ErrorCode.UNKNOWN).isinstance(Exception)


@enum.unique
class NessieError:
    def __init__(self, reason: str, status: int, error_code: ErrorCode):
        self.reason = reason
        self.status = status
        self.error_code = error_code


def test_conversion(error_code: ErrorCode) -> None:
    ex = ex(error_code)
    assert ex is not None
    assert isinstance(ex, Exception)
    assert ex.getErrorCode() == error_code

# Test cases
test_unknown()
for code in [code for code in ErrorCode]:
    if code != ErrorCode.UNKNOWN:
        test_conversion(code)

```

Please note that Python does not have direct equivalent of Java's `@Test` and `@ParameterizedTest`. The testing framework used here is simple assertion.