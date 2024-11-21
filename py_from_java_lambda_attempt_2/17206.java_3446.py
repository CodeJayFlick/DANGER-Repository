Here is the translation of the Java code to Python:
```
# Licensed under Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0

import typing as t

class PayloadFormatter:
    """PayloadFormatter format the payload to the messages."""

    def __init__(self):
        pass  # No constructor needed, just an interface

    @t.overload
    def format(self, payload: bytes) -> t.List[t.Any]:
        ...

    @format.register
    def _(self, payload: str) -> t.List[str]:  # For string payloads
        raise NotImplementedError("Format for string payloads not implemented")

    def get_name(self) -> str:
        """Get the formatter name."""
        return "PayloadFormatter"
```
Note that I've used Python's type hints to indicate the expected types of variables and function parameters. In particular, `t.List[t.Any]` indicates a list of any type (equivalent to Java's raw `List`), while `t.overload` is used to define multiple overloads for the same method.

Also, I've implemented only one overload for the `format` method, which takes a bytes object as input. You would need to add more overloads or implement other logic to handle different types of payloads (e.g., strings).