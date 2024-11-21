Here is the translation of the given Java code into Python:

```Python
class IsSwimming:
    def __init__(self):
        pass

    @property
    def description(self):
        return "Checks whether a living entity is swimming."

    @property
    def examples(self):
        return ["player is swimming"]

    @property
    def name(self):
        return "Is Swimming"

    @property
    def required_plugins(self):
        return "1.13 or newer"

    @property
    def since(self):
        return "2.3"


def check(e):
    if hasattr(e, 'is_swimming'):
        return e.is_swimming()
    else:
        raise AttributeError("The entity is not a living entity")


class PropertyCondition(IsSwimming):
    pass


if __name__ == "__main__":
    # You can test the class here
    print(check(LivingEntity()))
```

Please note that Python does not have direct equivalent of Java's annotations, so I've used properties to achieve similar functionality. Also, `LivingEntity` is a fictional class in this context and should be replaced with your actual entity class if you're using it as an argument for the `check` function.

Also, please remember that Python doesn't support static methods or blocks like Java does. The equivalent of Java's static block would be executed when the script is run directly (i.e., not imported), which might not be what you want in this case.