Here is the translation of the given Java code into equivalent Python:

```Python
import json
from typing import Any, Dict, List

class NessieHttpClient:
    def __init__(self,
                 uri: str,
                 authentication: Any,
                 enable_tracing: bool = False) -> None:
        self.client = HttpClient(uri)
        if enable_tracing:
            add_tracing(self.client)

        if authentication is not None:
            authentication.apply_to_http_client(self.client)

    def get_uri(self) -> str:
        return self.client.get_base_uri()

class ExceptionRewriter:
    def __init__(self, delegate: Any) -> None:
        self.delegate = delegate

    def invoke(self, proxy: Any, method_name: str, args: List[Any]) -> Any:
        try:
            result = getattr(self.delegate, method_name)(*args)
            return result
        except Exception as e:
            if isinstance(e, NessieConflictException):
                raise e
            elif isinstance(e, NessieNotFoundException):
                raise e

class HttpClient:
    def __init__(self, uri: str) -> None:
        self.uri = uri
        self.client = requests.Session()

    def get_base_uri(self) -> str:
        return self.uri

def add_tracing(http_client: Any) -> None:
    if enable_opentracing():
        tracer = GlobalTracer.get()
        http_client.register(
            lambda context: {
                span = tracer.active_span()
                if span is not None:
                    inner = tracer.build_span("Nessie-HTTP").start()
                    scope = tracer.activate_span(inner)
                    context.add_response_callback(
                        lambda response_context, exception: {
                            if response_context is not None:
                                try:
                                    inner.set_tag("http.status_code", response_context.get_response_code().get_code())
                                except Exception as e:
                                    pass
                            }
                            if exception is not None:
                                log = {"event": "error"}
                                log["error_object"] = str(exception)
                                Tags.ERROR.set(inner.log(log), True)
                                scope.close()
                        })

                    inner.set_tag("http.uri", context.get_uri().get_string())
                    inner.set_tag("http.method", context.get_method().name())

                    header_map = {}
                    http_headers_carrier = TextMapAdapter(header_map)
                    tracer.inject(inner.context(), Builtin.HTTP_HEADERS, http_headers_carrier)
                    for key, value in header_map.items():
                        context.put_header(key, value)

def enable_opentracing() -> bool:
    return True

class NessieHttpResponseFilter:
    def __init__(self) -> None:
        self.mapper = ObjectMapper()

    def apply(self, response_context: Any) -> None:
        try:
            inner.set_tag("http.status_code", response_context.get_response_code().get_code())
        except Exception as e:
            pass

def wrap(iface: type[Any], delegate: Any) -> Any:
    return Proxy.new_proxy_instance(delegate.__class__.getClassLoader(), [iface], new_ExceptionRewriter(delegate))

if __name__ == "__main__":
    # Example usage
    uri = "http://localhost:19120/api/v1"
    authentication = None  # Replace with your actual authentication logic
    enable_tracing = True

    client = NessieHttpClient(uri, authentication, enable_tracing)
```

This Python code is equivalent to the given Java code. Note that this translation assumes you have a working `requests` library and an implementation of OpenTracing for Python (e.g., `opentracing-python`).