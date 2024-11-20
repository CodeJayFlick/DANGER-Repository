class MnemonicFieldMouseHandler:
    def __init__(self):
        self.SUPPORTED_CLASSES = [MnemonicFieldLocation]

    def field_element_clicked(self, clicked_object: object, source_navigatable: Navigatable,
                               location: ProgramLocation, mouse_event: MouseEvent, service_provider: ServiceProvider) -> bool:
        if mouse_event.get_click_count() != 2 or mouse_event.get_button() != 1:
            return False

        program_manager = service_provider.get_service(ProgramManager)
        if program_manager is None:
            return False
        current_program = program_manager.get_current_program()
        listing = current_program.get_listing()
        code_unit = listing.get_code_unit_at(location.get_address())
        return self.check_mem_references(code_unit, service_provider)

    def check_mem_references(self, code_unit: CodeUnit, service_provider: ServiceProvider) -> bool:
        if code_unit is None:
            return False

        refs = code_unit.get_mnemonic_references()
        if len(refs) > 1:
            outgoing_references = []
            for reference in refs:
                outgoing_references.append(OutgoingReferenceEndpoint(reference,
                                                                      ReferenceUtils.is_offcut(code_unit.get_program(), reference.get_to_address())))
            model = IncomingReferencesTableModel("Mnemonic", service_provider, code_unit.get_program(),
                                                 outgoing_references, None)
            if service_provider.get_service(TableService) is not None:
                nav = NavigationUtils.get_active_navigatable()
                service_provider.get_service(TableService).show_table("Mnemonic", "Mnemonic", model,
                                                                     "References", nav)
                return True
        elif len(refs) == 1:
            symbol_table = code_unit.get_program().get_symbol_table()
            symbol = symbol_table.get_symbol(refs[0])
            if symbol is not None:
                loc = symbol.get_program_location()
            else:
                loc = AddressFieldLocation(code_unit.get_program(), refs[0].get_to_address())
            go_to_service = service_provider.get_service(GoToService)
            if go_to_service is not None:
                return go_to_service.go_to(loc)

        return False

    def get_supported_program_locations(self) -> list:
        return self.SUPPORTED_CLASSES
