Here is your Java code in Python:

```python
import ghidra.program.model.address as Address
from typing import List, Set, Tuple

class SimpleDiffUtility:
    def __init__(self):
        pass

    @staticmethod
    def getCompatibleAddressSpace(addr_space: 'memory', other_program: Program) -> Optional[Symbol]:
        if addr_space.isMemory():
            return None  # TODO: should we handle improperly aligned offcut register varnodes within big endian registers
        else:
            return None

    def getCompatibleVariableStorage(self, program: Program, storage: Variable) -> Optional[Variable]:
        pass

    @staticmethod
    def getMatchingExternalLocation(program: 'memory', other_program: Program) -> ExternalLocation:
        if (program == null):
            return None  # TODO: should we handle improperly aligned offcut register varnodes within big endian registers
        else:
            return None