Here is the translation of the given Java code into equivalent Python:

```Python
class RainbowFish:
    def __init__(self, name: str, age: int, length_meters: float, weight_tons: float):
        self.name = name
        self.age = age
        self.length_meters = length_meters
        self.weight_tons = weight_tons

# Note that Python does not have a direct equivalent to Java's Serializable interface.
```

Note that in the above code:

- The `@Getter` and `@RequiredArgsConstructor` annotations are specific to Lombok, which is a popular library for simplifying boilerplate code. Since we're translating this into Python, these aren't necessary.

- In Python, there isn't an equivalent of Java's `Serializable` interface. If you want your class to be serializable in Python, you would typically use the built-in `pickle` module or another serialization library like `json`.

- The `private static final long serialVersionUID = 1L;` line is specific to Java and serves as a version number for deserialization purposes. This isn't necessary in Python.

The equivalent class definition in Python does not include these annotations, but it still provides the same functionality by allowing you to create instances of RainbowFish with specified name, age, length_meters, and weight_tons attributes.