Here is the translation of the Java interface `BlockStreamHandle` to a Python abstract class:

```python
from abc import ABC, abstractmethod
import io

class BlockStreamHandle(ABC):
    @abstractmethod
    def open_block_stream(self) -> object:
        """Invoked by client to establish the remote connection and return 
           the opened block stream.
        
        Returns:
            connected/open block stream
        
        Raises:
            Exception (not explicitly IOException, but similar concept)
        """
```

Note that in Python:

* We use an abstract class (`ABC`) instead of an interface.
* The `@abstractmethod` decorator is used to define a method that must be implemented by any subclass.
* The return type and exception types are not as strictly defined as they would be in Java, but the concept remains similar.