Here is the translation of the Java interface into a Python class:

```Python
class ViewListener:
    def __init__(self):
        pass

    def view_changed(self, fp: 'FieldPanel', index: int, x_offset: int, y_offset: int) -> None:
        """
        Notifies the listener that the top of the screen has changed position.

        Args:
            fp (FieldPanel): The field panel whose view changed.
            index (int): The index of the layout at the top of the screen.
            x_offset (int): The x coordinate of the layout displayed at the left of the screen.
            y_offset (int): The y coordinate of the layout displayed at the top of the screen.

        Returns:
            None
        """
        pass

```

Note that Python does not have a direct equivalent to Java's interfaces. Instead, we can use abstract classes or protocols from third-party libraries like `typing` and `abc`. However, for simplicity, I've used a regular class here with no implementation in the methods (since they are supposed to be implemented by subclasses).