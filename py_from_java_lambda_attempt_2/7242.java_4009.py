Here is the translation of the given Java code into Python:

```Python
class FailureKind:
    NO_FAILURE = 'NO_FAILURE'
    SOFT_FAILURE = 'SOFT_FAILURE'
    HARD_FAILURE = 'HARD_FAILURE'

# You can use this class like below:
failure_kind = FailureKind.SOFT_FAILURE
print(failure_kind)
```

Note that in Java, you have an `enum` which is a special type of class. In Python, we don't have direct equivalent to enums but we can achieve similar functionality using classes and constants.