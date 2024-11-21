Here's a translation of your Java interface into Python:

```Python
class AnnotatedStringHandler:
    DUMMY_MOUSE_HANDLER = DummyMouseHandler()

    def __init__(self):
        pass

    @classmethod
    def create_annotated_string(cls, prototype_string: AttributedString, text: list[str], program: Program) -> AttributedString:
        raise NotImplementedError("Subclasses must implement this method")

    def get_supported_annotations(self) -> list[str]:
        raise NotImplementedError("Subclasses must implement this method")

    @classmethod
    def handle_mouse_click(cls, annotation_parts: list[str], source_navigatable: Navigatable, service_provider: ServiceProvider) -> bool:
        return False

    def get_display_string(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")

    def get_prototype_string(self) -> str:
        raise NotImplementedError("Subclasses must implement this method")


class DummyMouseHandler(AnnotatedStringHandler):
    @classmethod
    def handle_mouse_click(cls, location: ProgramLocation, mouse_event: MouseEvent, service_provider: ServiceProvider) -> bool:
        return False


# Note that AttributedString and Navigatable are not part of the standard Python library.
# You would need to define these classes or use existing ones if they exist in your project.

class AttributedString:
    pass

class ProgramLocation:
    pass

class Navigatable:
    pass

class ServiceProvider:
    pass
```

This translation maintains the same structure and method signatures as the original Java interface. However, note that Python does not have direct equivalents to some of the Java classes (like `AttributedString`, `ProgramLocation`, `Navigatable`, and `ServiceProvider`), so you would need to define these yourself or use existing ones if they exist in your project.