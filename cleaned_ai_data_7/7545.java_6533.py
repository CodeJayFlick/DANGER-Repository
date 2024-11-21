class SetFormatDialogComponentProvider:
    def __init__(self, default_format_manager, current_format_manager, serviceProvider, program, view):
        self.default_format_manager = default_format_manager
        self.current_format_manager = current_format_manager
        self.program = program
        self.view = view

        super().__init__("Edit Code Layout", True, False, True, False)

        self.set_preferred_size(600, 500)
        
        work_panel = self.create_work_panel()
        self.add_work_panel(work_panel)
        self.add_ok_button()
        self.add_cancel_button()

    def create_work_panel(self):
        container = JPanel(BorderLayout())
        listing_panel = self.create_listing_panel()
        listing_panel.show_header(True)

        container.add(listing_panel, BorderLayout.CENTER)

        return container

    def create_listing_panel(self):
        format_manager_copy = self.current_format_manager.clone()
        panel = ListingPanel(format_manager_copy, self.program)
        panel.set_view(self.view)
        
        return panel

    @property
    def new_format_manager(self):
        return self._new_format_manager

    @new_format_manager.setter
    def new_format_manager(self, value):
        self._new_format_manager = value

    def ok_callback(self):
        self.new_format_manager = self.listing_panel.get_format_manager()
        self.close()

    def cancel_callback(self):
        self.new_format_manager = None
        super().cancel_callback()

    @property
    def listing_panel(self):
        return self._listing_panel

    @listing_panel.setter
    def listing_panel(self, value):
        self._listing_panel = value

    def close(self):
        super().close()
        self.listing_panel.dispose()

    def get_action_context(self, event):
        if not event:
            return None
        
        header_panel = self.listing_panel.get_field_header()
        
        if header_panel and header_panel.is_ancestor_of(event.component):
            fh_loc = header_panel.get_field_header_location(event.point)
            
            return ActionContext().set_context_object(fh_loc)

    def get_field_header(self):
        return self.listing_panel.get_field_header()

class CustomResetAllFormatAction:
    def __init__(self):
        super().__init__("Reset All Formats", "Edit Code Layout", False)

        self.set_popup_menu_data(MenuData(["Reset All Formats"], None, "format"))
        self.set_enabled(True)

    @property
    def is_enabled_for_context(self):
        return lambda context: isinstance(context.context_object, FieldHeaderLocation)

    def action_performed(self, context):
        user_choice = OptionDialog.show_option_dialog(self.listing_panel, "Reset All Formats?", 
            "There is no undo for this action.\n" + 
                "Are you sure you want to reset all formats?",
            "Continue", OptionDialog.WARNING_MESSAGE)
        
        if user_choice == OptionDialog.CANCEL_OPTION:
            return
        
        listing_format_manager = self.listing_panel.get_format_manager()
        save_state = SaveState()

        self.default_format_manager.save_state(save_state)

        # update the dialog's GUI (which will later be used as the new format if the
        # user presses OK)
        listing_format_manager.read_state(save_state)

class CustomResetFormatAction:
    def __init__(self):
        super().__init__("Reset Format", "Edit Code Layout", False)

        self.set_popup_menu_data(MenuData(["Reset Format"], None, "format"))
        self.set_enabled(True)

    @property
    def is_enabled_for_context(self):
        return lambda context: isinstance(context.context_object, FieldHeaderLocation)

    def action_performed(self, context):
        field_header = self.listing_panel.get_field_header()
        
        if not field_header:
            return
        
        index = field_header.selected_index
        original_model = self.default_format_manager.model(index)
        original_xml = original_model.save_to_xml()

        # update the dialog's GUI (which will later be used as the new format if the
        # user presses OK)
        listing_format_manager = self.listing_panel.get_format_manager()
        current_model = listing_format_manager.model(index)
        current_model.restore_from_xml(original_xml)

class MenuData:
    def __init__(self, items=None, mnemonic_index=-1, help_tag=""):
        super().__init__()
        
        if not items:
            items = []
        
        self.items = items
        self.mnemonic_index = mnemonic_index
        self.help_tag = help_tag

# Testing
def get_field_header():
    return listing_panel.get_field_header()
