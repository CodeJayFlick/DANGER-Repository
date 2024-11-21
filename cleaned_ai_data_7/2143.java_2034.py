class DebuggerModelFactory:
    def __init__(self):
        pass

    def is_compatible(self) -> bool:
        return True


# Note: The following imports are not necessary for this specific conversion,
#       but they might be useful in a larger context.
from abc import ABC, abstractmethod
import ghidra.util.classfinder.extension_point as ExtensionPoint
