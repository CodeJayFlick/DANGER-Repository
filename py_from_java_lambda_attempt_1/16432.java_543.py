Here's the equivalent Python code:

```Python
class CheckConsistencyException(Exception):
    def __init__(self, error_message: str) -> None:
        super().__init__(f"check consistency failed, error message={error_message}")

CHECK_STRONG_CONSISTENCY_EXCEPTION = CheckConsistencyException("strong consistency, sync with leader failed")
CHECK_MID_CONSISTENCY_EXCEPTION = CheckConsistencyException(
    "mid consistency, localAppliedId is smaller than the leaderCommitId"
)
```

Note that Python does not have a direct equivalent to Java's `public` and `static final`. In Python, everything is public by default (i.e., it can be accessed from anywhere), so there's no need for an explicit access modifier. The concept of static methods or variables also doesn't exist in the same way as they do in Java; instead, you would typically define them at the class level and use them like any other method or variable on that class.