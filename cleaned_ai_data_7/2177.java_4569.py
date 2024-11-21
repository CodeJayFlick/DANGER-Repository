class TargetAttachable:
    def __init__(self):
        pass

# Note: In Python, we don't have a direct equivalent for interfaces like in Java.
# Instead, you can use abstract classes or protocols. Here's an example using 
# protocol (a new feature introduced in Python 3.8):

from typing import Protocol

class TargetAttachableProtocol(Protocol):
    pass
