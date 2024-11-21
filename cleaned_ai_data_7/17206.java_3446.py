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
