Here's the translation of the given Java interface into a Python class:

```Python
class SubroutineBlockModel:
    """Subroutine block model."""

    def __init__(self):
        pass

    def get_base_subroutine_model(self) -> 'SubroutineBlockModel':
        """
        Get the underlying base subroutine model.
        
        This is generally the MultEntSubModel (M-Model).
        If there is no base model, this subroutine model is returned.

        :return: Base subroutine model
        """
        return self  # For now, returning itself as a placeholder. You might want to implement actual logic here.
```

Note that Python doesn't have direct support for interfaces like Java does. Instead, we use abstract classes or protocols (in the context of type hints) to define contracts that must be implemented by subclasses. In this case, I've chosen an abstract class (`SubroutineBlockModel`) as a translation equivalent.