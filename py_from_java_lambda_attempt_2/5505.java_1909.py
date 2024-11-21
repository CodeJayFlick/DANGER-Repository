Here is the translation of the Java code to Python:
```
class OpenCloseFieldMouseHandler:
    SUPPORTED_CLASSES = [OpenCloseField]

    def field_element_clicked(self, clicked_object: object, source_navigatable: Navigatable,
                               location: ProgramLocation, mouse_event: MouseEvent) -> bool:
        if mouse_event.button != 1:
            return False

        field = OpenCloseField(clicked_object)
        field.toggle_open_close_state()
        return True

    def get_supported_program_locations(self):
        return self.SUPPORTED_CLASSES


class Navigatable:
    pass


class ProgramLocation:
    pass


class MouseEvent:
    button: int
    pass


class OpenCloseField:
    def toggle_open_close_state(self) -> None:
        # implement me!
        pass

# Note: In Python, we don't need to define the classes for MouseEvent and Navigatable as they are built-in.
```
Note that I've kept the `OpenCloseField` class abstract since its implementation is not provided in the original Java code. You would need to fill in the implementation of this method depending on your specific use case.

Also, Python does not have a direct equivalent to Java's static variables or methods. Instead, we define them as instance variables and methods if they are meant to be shared across instances. In this case, I've defined `SUPPORTED_CLASSES` as an instance variable since it seems to be related to the class itself rather than being a global constant.