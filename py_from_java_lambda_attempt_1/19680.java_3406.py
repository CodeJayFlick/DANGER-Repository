Here is a translation of the Java code into equivalent Python:

```Python
import.bukkit.block.Sign as BukkitSign
from typing import List, Tuple, Optional

class SignText:
    def __init__(self):
        self.line = None  # type: Optional[int]
        self.block = None  # type: Optional[BukkitSign]

    @property
    def line(self) -> int:
        return self._line

    @line.setter
    def line(self, value: int) -> None:
        if not isinstance(value, int):
            raise TypeError("Line must be an integer")
        self._line = value

    @property
    def block(self) -> BukkitSign:
        return self._block

    @block.setter
    def block(self, value: BukkitSign) -> None:
        if not isinstance(value, BukkitSign):
            raise TypeError("Block must be a Sign object from the Bukkit library")
        self._block = value

    def get(self, event: Optional[Tuple]) -> List[str]:
        if event is None or len(event) == 0:
            return []
        
        line_number = int(self.line)
        block = self.block
        
        if isinstance(block, BukkitSign):
            sign_lines = list(block.getLines())
            if line_number < 4 and line_number >= 1:
                return [sign_lines[line_number - 1]]
            
        return []

    def __str__(self) -> str:
        return f"line {self.line} of {self.block}"
```

This Python code is a direct translation from the Java code. It defines a class `SignText` with properties for line number and block, which are used to get the text on a sign in Minecraft using Bukkit library.