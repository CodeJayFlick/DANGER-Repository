Here is the translation of the Java code to Python:
```
class ErrorFieldMouseHandler:
    def __init__(self):
        self.SUPPORTED_CLASSES = [ErrorListingField]

    def field_element_clicked(self, clicked_object: object, source_navigatable: Navigatable,
                               location: ProgramLocation, mouse_event: MouseEvent,
                               service_provider: ServiceProvider) -> bool:
        if mouse_event.get_click_count() != 2 or mouse_event.get_button() != MouseEvent.BUTTON1:
            return False
        error_field = ErrorListingField(clicked_object)
        field_name = error_field.field_factory().get_field_name()
        msg.show_error(self, None, "Listing Field Exception",
                       f"Exception occurred while rendering '{field_name}' field", error_field.getThrowable())
        return True

    def get_supported_program_locations(self) -> list:
        return self.SUPPORTED_CLASSES
```
Note that I've used Python's type hints to indicate the expected types of variables and function parameters. This is not strictly necessary, but it can help with code readability and maintainability.

Also, I've replaced Java's `public` access modifier with nothing (i.e., no explicit access modifier), since in Python, there are no explicit access modifiers like public or private. Instead, you rely on conventions such as prefixing variable names with underscores to indicate that they should be treated as internal implementation details.

Finally, I've used the `f` string notation to create a formatted string for the error message, which is equivalent to Java's concatenation using the `+` operator.