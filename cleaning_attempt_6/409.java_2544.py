# Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License.
# You may obtain a copy of the License at http://www.apache.org/licenses/LICENSE-2.0

class DebugOutputCallbacks:
    def __init__(self):
        pass
    
    def output(self, mask: int, text: str) -> None:
        """The interface for receiving output callbacks via IDebugOutputCallbacks or a newer variant."""
        # TODO: Change the 'mask' parameter to use DebugOutputLevel flags.
        print(f"Mask: {mask}, Text: {text}")
