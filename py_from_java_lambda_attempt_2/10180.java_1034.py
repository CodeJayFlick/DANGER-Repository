Here is the translation of the Java code to Python:

```
class DoNotContinue:
    def __init__(self):
        pass

DoNotContinue = type('DoNotContinue', (), {})
@DoNotContinue
def do_not_continue():
    """marker interface"""
    pass
```