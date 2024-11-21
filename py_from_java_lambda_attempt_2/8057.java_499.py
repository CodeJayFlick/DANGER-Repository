Here is the translation of the given Java code into Python:

```Python
class AbstractGlobalManagedProcedureMsSymbol:
    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader', str_type: 'StringParseType'):
        super().__init__(pdb, reader, str_type)

# Note that this is an abstract class in Java and does not have a direct equivalent
# in Python. However, we can use the ABC (Abstract Base Class) module to create
# an abstract base class.
from abc import ABC, abstractmethod

class AbstractManagedProcedureMsSymbol(ABC):
    @abstractmethod
    def __init__(self, pdb: 'AbstractPdb', reader: 'PdbByteReader'):
        pass

```

Please note that Python does not have direct equivalent of Java's `abstract` keyword. In the above code, we are using ABC (Abstract Base Class) module to create an abstract base class in Python.

Also, please note that this is a translation and may require some modifications based on your specific requirements.