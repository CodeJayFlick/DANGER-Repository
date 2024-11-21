Here is the translation of the given Java code into equivalent Python:

```Python
import enum

class DependentService:
    def __init__(self):
        pass

    @property
    def override(self) -> type:
        return Sentinel


@enum.unique
class Sentinel(enum.Enum):
    # None
    pass
```

Note that the `@interface` and `@Target`, `@Retention` annotations are not directly translatable to Python, as they serve a specific purpose in Java (defining an annotation). In this translation, I've omitted these annotations.