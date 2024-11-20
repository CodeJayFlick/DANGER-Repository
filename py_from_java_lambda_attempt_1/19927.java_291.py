Here is the equivalent Python code:

```Python
class Experience:
    def __init__(self):
        self.xp = -1
    
    def __init__(self, xp: int):
        self.xp = xp
    
    @property
    def xP(self) -> int:
        return 1 if self.xp == -1 else self.xp

    @property
    def internalXP(self) -> int:
        return self.xp

    def __str__(self) -> str:
        return "xp" if self.xp == -1 else f"{self.xp} xp"

    def __hash__(self):
        prime = 31
        result = 1
        result *= prime + self.xp
        return result
    
    def __eq__(self, other: object) -> bool:
        if self is other:
            return True
        if not isinstance(other, Experience):
            return False
        if self.xp != other.xp:
            return False
        return True

```

Note that Python does not have direct equivalents for Java's `@Override`, `@Nullable` and `YggdrasilSerializable`.