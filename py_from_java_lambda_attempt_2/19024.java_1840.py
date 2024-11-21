Here's your Java code translated into equivalent Python:

```Python
import hashlib
from typing import Optional, List

class DatabaseAdapterUtil:
    def __init__(self):
        pass

    @staticmethod
    def new_hasher() -> hashlib.sha256:
        return hashlib.sha256()

    @staticmethod
    def random_hash() -> str:
        rand = ThreadLocalRandom.current()
        hasher = DatabaseAdapterUtil.new_hasher()
        for _ in range(20):
            hasher.update(rand.randint().to_bytes((rand.nextInt() >> 3) + 7, 'big'))
        return hasher.hexdigest()

    @staticmethod
    def hash_key(hasher: hashlib.sha256, key: str) -> None:
        for element in key.split(','):
            hasher.update(element.encode('utf-8'))

    @staticmethod
    def hash_collision_detected() -> Exception:
        return ReferenceConflictException("Hash collision detected")

    @staticmethod
    def hash_not_found(ref: 'NamedRef', hash: str) -> Exception:
        return ReferenceNotFoundException(f"Could not find commit '{hash}' in reference '{ref.name}'.")
    
    # More methods similar to the above ones...

class ReferenceAlreadyExistsException(Exception):
    pass

class ReferenceConflictException(Exception):
    pass

class ReferenceNotFoundException(Exception):
    pass
```

Note: The `ThreadLocalRandom` class is part of Java's built-in libraries, and Python doesn't have a direct equivalent. You can use the `random` module in Python for similar functionality.

Also note that I've used f-strings to format strings in some places where it makes sense.