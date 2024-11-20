Here is the equivalent Python code:

```Python
import json
from unittest import TestCase


class NessieError:
    def __init__(self, message: str, error_code: int, status: int, reason: str, server_stack_trace: str):
        self.message = message
        self.error_code = error_code
        self.status = status
        self.reason = reason
        self.server_stack_trace = server_stack_trace

    def get_full_message(self) -> str:
        return f"{self.reason} (HTTP/{self.status}): {self.message}\n{self.server_stack_trace}"


class TestNessieError(TestCase):
    def test_full_message(self):
        e = NessieError(
            message="message",
            error_code=0,
            status=500,
            reason="Internal Server Error",
            server_stack_trace="foo.bar.InternalServerError\nat some.other.Class"
        )
        self.assertEqual(e.get_full_message(), f"Internal Server Error (HTTP/500): message\n{e.server_stack_trace}")

        e = NessieError(
            from_=e,
            client_processing_exception=Exception("processingException")
        )
        self.assertTrue(e.get_full_message().startswith(f"{e.reason} (HTTP/{e.status}): {e.message}\n{e.server_stack_trace}\njava.lang.Exception: processingException\nat org.projectnessie.error.TestNessieError.test_full_message")

    def test_json_round_trip(self):
        e0 = NessieError(
            message="message",
            error_code=0,
            status=500,
            reason="Internal Server Error",
            server_stack_trace="foo.bar.InternalServerError\nat some.other.Class"
        )
        e0.client_processing_exception = Exception("processingException")

        json_str = json.dumps(e0.__dict__)
        e1 = NessieError(**json.loads(json_str))

        self.assertIsNone(getattr(e1, "client_processing_exception", None))  # not propagated through JSON

        e2 = NessieError(from_=e0, client_processing_exception=None)
        self.assertEqual(str(e1), str(e2))
```

Please note that Python does not have direct equivalent of Java's `@Test` annotation. Instead, we use the built-in testing framework unittest and define a test class with methods starting with "test_".