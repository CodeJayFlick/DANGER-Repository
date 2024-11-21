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
