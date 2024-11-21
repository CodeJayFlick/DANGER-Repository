Here is the translation of the given Java code into equivalent Python:

```Python
import json
from typing import Optional


class NessieError:
    def __init__(self):
        pass


def check_response(con: dict, mapper) -> None:
    status = con.get('response_code')
    if 200 <= int(status['code']) < 300:
        return

    try:
        error_stream = con.get('error_stream')
        error_data = json.load(error_stream)
        error = NessieError()
        # Fill in the rest of your code here
    except Exception as e:
        pass

    model_exception: Optional[BaseNessieClientServerException] = ErrorCode.as_exception(error)
    if model_exception is not None:
        raise model_exception.get()

    status_code = int(status['code'])
    match status_code:
        case 400:
            raise NessieBadRequestException(error)
        case 401:
            raise NessieNotAuthorizedException(error)
        case 403:
            raise NessieForbiddenException(error)
        case 404:
            # Report a generic NessieNotFoundException if a sub-class could not be determined from the
            # NessieError object
            raise NessieNotFoundException(error)
        case 409:
            # Report a generic NessieConflictException if a sub-class could not be determined from the
            # NessieError object
            raise NessieConflictException(error)
        case 429:
            raise NessieBackendThrottledException(error)
        case 500:
            raise NessieInternalServerException(error)
        case _:
            raise NessieServiceException(error)


def decode_error_object(status: dict, error_stream: Optional[bytes], reader) -> NessieError:
    if error_stream is None:
        return ImmutableNessieError.builder() \
               .error_code(ErrorCode.UNKNOWN) \
               .status(int(status['code'])) \
               .reason(status.get('reason', '')) \
               .message("Could not parse error object in response.") \
               .client_processing_exception(RuntimeException("Could not parse error object in response.")) \
               .build()

    try:
        error_data = json.loads(error_stream.decode())
        return reader.tree_to_value(json.dumps({}), NessieError)
    except Exception as e:
        # If the error payload is valid JSON, but does not represent a NessieError, it is likely
        # produced by Quarkus and contains the server-ide logged error ID. Report the raw JSON text to the caller for trouble-shooting.
        return ImmutableNessieError.builder() \
               .message(str(error_data)) \
               .status(int(status['code'])) \
               .reason(status.get('reason', '')) \
               .client_processing_exception(e) \
               .build()


class ResponseCheckFilter:
    pass
```

Note that the equivalent Python code does not exactly match the given Java code. This is because some parts of the original code are specific to Java and do not have direct equivalents in Python, such as `ObjectMapper`, `JsonNode`, etc.