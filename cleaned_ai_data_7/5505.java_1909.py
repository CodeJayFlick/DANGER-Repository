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
