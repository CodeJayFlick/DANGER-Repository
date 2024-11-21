class XRefFieldMouseHandler:
    def __init__(self):
        self.SUPPORTED_CLASSES = [XRefFieldLocation.__name__, XRefHeaderFieldLocation.__name__]

    def field_element_clicked(self, clicked_object, source_navigatable, location, mouse_event, service_provider):
        if mouse_event.get_click_count() != 2 or mouse_event.get_button() != 1:
            return False

        go_to_service = service_provider.get(GoToService)
        if go_to_service is None:
            return False

        # If I double-click on the XRef Header, show references to this place
        if self.is_xref_header_location(location):
            self.show_x_ref_dialog(source_navigatable, location, service_provider)
            return True

        referenced_address = self.get_from_reference_address(location)
        clicked_text = str(clicked_object)  # equivalent of getText() in Java
        is_invisible_xref = XRefFieldFactory.MORE_XREFS_STRING == clicked_text
        if is_invisible_xref:
            self.show_x_ref_dialog(source_navigatable, location, service_provider)
            return True

        return self.go_to(source_navigatable, referenced_address, go_to_service)

    def is_xref_header_location(self, location):
        return isinstance(location, XRefHeaderFieldLocation)

    def get_text(self, clicked_object):
        if isinstance(clicked_object, TextField):
            return str(clicked_object.get_text())
        elif isinstance(clicked_object, FieldElement):
            return str(clicked_object.get_text())
        else:
            return str(clicked_object)

    def go_to(self, source_navigatable, referenced_address, go_to_service):
        if referenced_address is not None:
            return go_to_service.go_to(source_navigatable, referenced_address)
        return False

    def show_x_ref_dialog(self, navigatable, location, service_provider):
        table_service = service_provider.get(TableService)
        if table_service is None:
            return
        refs = XReferenceUtils.get_all_xrefs(location)
        XReferenceUtils.show_xrefs(navigatable, service_provider, table_service, location, refs)

    def get_referred_to_location(self, source_navigatable, location):
        program = source_navigatable.get_program()
        return CodeUnitLocation(program, self.go_to_reference_address(location), 0, 0, 0)

    SUPPORTED_PROGRAM_LOCATIONS = [XRefFieldLocation.__name__, XRefHeaderFieldLocation.__name__]

    def get_supported_program_locations(self):
        return self.SUPPORTED_CLASSES
