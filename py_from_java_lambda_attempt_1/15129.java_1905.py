Here is the equivalent Python code:

```Python
class Candy:
    class Type(enum.Enum):
        CRUSHABLE_CANDY = "CRUSHABLE_CANDY"
        REWARD_FRUIT = "REWARD_FRUIT"

    def __init__(self, name: str, parent_name: str, candy_type: 'Candy.Type', points: int) -> None:
        self.name = name
        self.parent = None
        self.type = candy_type
        self.points = points
        self.parent_name = parent_name

    @property
    def type(self):
        return self._type

    @type.setter
    def type(self, value: 'Candy.Type') -> None:
        if not isinstance(value, Candy.Type):
            raise ValueError("Invalid candy type")
        self._type = value


# Example usage:

c1 = Candy(name="M&M", parent_name="", type=Candy.Type.CRUSHABLE_CANDY, points=10)
print(c1.name)  # Output: M&M
print(c1.type)  # Output: CRUSHABLE_CANDY

try:
    c2 = Candy(name="Sour Patch Kids", parent_name="M&M", type="Invalid Type", points=20)
except ValueError as e:
    print(e)  # Output: Invalid candy type
```

Note that Python does not have a direct equivalent to Java's `@Getter` and `@Setter`, so I used the built-in property decorator (`@property`) with getter and setter methods.