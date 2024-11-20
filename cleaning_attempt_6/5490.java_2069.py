class ImageFactoryFieldMouseHandler:
    SUPPORTED_CLASSES = [ImageFactoryField]

    def field_element_clicked(self, clicked_object: object, navigatable: Navigatable,
                               location: ProgramLocation, mouse_event: MouseEvent,
                               service_provider: ServiceProvider) -> bool:
        if mouse_event.get_button() != 1:
            return False

        if mouse_event.get_click_count() == 1:
            return self.handle_single_click(mouse_event, navigatable, location)

        return False

    def get_supported_program_locations(self):
        return [ImageFactoryField]

    def handle_single_click(self, mouse_event: MouseEvent, navigatable: Navigatable,
                            location: ProgramLocation) -> bool:
        program = navigatable.get_program()
        listing = program.get_listing()
        code_unit = listing.get_code_unit_containing(location.get_address())
        if isinstance(code_unit, Data):
            data = code_unit
            value = data.get_value()
            if isinstance(value, Playable):
                (value).clicked(mouse_event)
                return True

        return False


class Navigatable:
    def get_program(self) -> object:
        pass  # Implement this method in your subclass


class ProgramLocation:
    def get_address(self) -> int:
        pass  # Implement this method in your subclass


class MouseEvent:
    def get_button(self) -> int:
        pass  # Implement this method in your subclass

    def get_click_count(self) -> int:
        pass  # Implement this method in your subclass
