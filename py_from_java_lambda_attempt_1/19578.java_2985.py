Here is a translation of the Java code into equivalent Python:

```Python
import hashlib
from typing import List, Tuple


class HashExpression:
    def __init__(self):
        self.algorithm = None

    @property
    def algorithm(self):
        return self._algorithm

    @algorithm.setter
    def algorithm(self, value: int):
        if value not in [0, 1]:
            raise ValueError("Invalid algorithm. Must be either MD5 (0) or SHA-256 (1).")
        self._algorithm = value

    def init(self, exprs: List[str], matched_pattern: int, is_delayed: bool, parse_result: Tuple[int]) -> bool:
        if len(exprs) != 1:
            raise ValueError("Invalid number of expressions. Must be exactly one.")
        self.expr = exprs[0]
        self.algorithm = parse_result[0] % 2
        return True

    def get(self, e: str, source: List[str]) -> Tuple[List[str], int]:
        if not all(isinstance(s, str) for s in source):
            raise ValueError("Invalid input. Must be a list of strings.")
        
        digest = None
        if self.algorithm == 0:
            digest = hashlib.md5()
        elif self.algorithm == 1:
            digest = hashlib.sha256()

        result = []
        for item in source:
            result.append(self.to_hex(digest.update(item.encode('utf-8')).digest()))
        
        return result, len(result)

    def to_hex(self, b: bytes) -> str:
        r = [f"{i:02x}" for i in bytearray(b)]
        return ''.join(r)

    def __str__(self):
        if self.expr is None:
            return "hash"
        else:
            return f"hash of {self.expr}"

    @property
    def expr(self) -> str:
        return self._expr

    @expr.setter
    def expr(self, value: str):
        self._expr = value


def main():
    expression = HashExpression()
    
    # Example usage
    expressions = ["hello", "world"]
    matched_pattern = 0
    is_delayed = False
    parse_result = (1,)
    result, length = expression.get(None, expressions)
    print(result)


if __name__ == "__main__":
    main()

```

This Python code defines a `HashExpression` class that mimics the behavior of the Java code. It uses the `hashlib` library to perform MD5 and SHA-256 hashing operations.

The `init`, `get`, and `to_hex` methods are equivalent to their counterparts in the original Java code. The `__str__` method returns a string representation of the expression, which is useful for debugging purposes.

In the example usage at the end of the script, we create an instance of the `HashExpression` class and use it to hash two strings using MD5 (the default algorithm).