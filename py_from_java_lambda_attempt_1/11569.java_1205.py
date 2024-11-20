Here is the translation of the given Java code into equivalent Python:

```Python
class OpBehaviorOtherNOP:
    def evaluate(self, emu: object, out: object, *inputs) -> None:
        # do nothing
        pass
```

Note that in this translation, I've kept the method signature similar to the original Java code. The `@Override` annotation is not necessary in Python as it's a dynamically-typed language and doesn't require explicit overriding of methods like Java does.

Also note that there are no direct equivalents for Java classes (`public class`) or interfaces (`implements OpBehaviorOther`). In Python, you can define functions directly inside the class.