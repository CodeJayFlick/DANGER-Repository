Here is the equivalent Python code:

```Python
class CakeLayer:
    def __init__(self):
        pass

    def __init__(self, name: str, calories: int):
        self.name = name
        self.calories = calories

    @property
    def id(self) -> int:
        return self._id

    @id.setter
    def id(self, value: int):
        self._id = value

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str):
        self._name = value

    @property
    def calories(self) -> int:
        return self._calories

    @calories.setter
    def calories(self, value: int):
        self._calories = value

    def __str__(self):
        return f"ID={self.id}, Name={self.name}, Calories={self.calories}"

    _cake = None

    @property
    def cake(self) -> object:
        return self._cake

    @cake.setter
    def cake(self, value: object):
        self._cake = value


# Example usage:

if __name__ == "__main__":
    layer1 = CakeLayer("Chocolate", 200)
    print(layer1)

    layer2 = CakeLayer("Vanilla", 150)
    print(layer2)

    layer3 = CakeLayer()
    layer3.name = "Strawberry"
    layer3.calories = 250
    print(layer3)

    # Cascade usage:
    cake_layer1 = CakeLayer("Chocolate Layer", 200)
    cake_layer2 = CakeLayer("Vanilla Layer", 150)
```

Please note that Python does not have direct equivalent of Java's `@Entity`, `@Id`, `@GeneratedValue` and other JPA annotations. The above code is a simple representation of the given Java class in Python, without any ORM (Object-Relational Mapping) functionality.