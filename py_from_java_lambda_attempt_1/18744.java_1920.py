Here is the translation of the Java code to Python:
```
import re

class GetCommitLogBuilder:
    def __init__(self):
        pass

    def until_hash(self, until_hash: str) -> 'GetCommitLogBuilder':
        if not isinstance(until_hash, str):
            raise ValueError("until_hash must be a string")
        pattern = re.compile(Validation.HASH_REGEX)
        if not pattern.match(until_hash):
            raise ValueError(f"Invalid hash format. Must match {Validation.HASH_MESSAGE}")
        return self

    def get(self) -> LogResponse:
        # implement the logic to retrieve the log response
        pass


class Validation:
    HASH_REGEX = r"[a-fA-F0-9]{40}"
    HASH_MESSAGE = "Invalid hash format"


class NessieNotFoundException(Exception):
    pass


class LogResponse:
    def __init__(self, ...):  # implement constructor logic here
        pass

# usage example
builder = GetCommitLogBuilder()
try:
    log_response = builder.until_hash("abc123").get()
except NessieNotFoundException as e:
    print(f"Error: {e}")
```
Note that I had to make some assumptions about the `Validation` and `NessieNotFoundException` classes, since they were not fully defined in the original Java code. Additionally, I did not implement the logic for retrieving the log response or constructing the `LogResponse` object, as those details are specific to your use case.