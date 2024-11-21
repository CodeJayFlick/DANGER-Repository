class StackEditorProvider:
    def __init__(self, plugin, function):
        self.plugin = plugin
        self.function = function
        self.program = function.get_program()
        self.stack_model = None
        super().__init__()

    def dispose(self):
        self.program.remove_listener(self)
        super().dispose()

    @staticmethod
    def get_provider_sub_title(function):
        program = function.get_program()
        return f"{function.name} ({program.domain_file_name})"

    def get_plugin(self):
        return self.plugin

    def get_name(self):
        return "Stack Editor"

    def get_help_name(self):
        return "Stack_Editor"

    def get_help_topic(self):
        return "StackEditor"

    def create_actions(self):
        actions = [
            ApplyAction(self),
            ClearAction(self),
            DeleteAction(self),
            PointerAction(self),
            ArrayAction(self),
            ShowComponentPathAction(self),
            EditComponentAction(self),
            EditFieldAction(self),
            HexNumbersAction(self)
        ]
        return actions

    def get_stack_name(self):
        if self.stack_model is None:
            return ""
        else:
            return self.stack_model.get_editor_stack().get_display_name()

    def get_function(self):
        editor_stack = self.stack_model.get_editor_stack()
        if editor_stack is None:
            return None
        else:
            return editor_stack.get_function()

    def is_editing(self, function_path):
        return self.get_dt_path() == function_path

    @property
    def program(self):
        return self._program

    @program.setter
    def program(self, value):
        self._program = value

    @property
    def stack_model(self):
        return self._stack_model

    @stack_model.setter
    def stack_model(self, value):
        self._stack_model = value

    def domain_object_restored(self, domain_object):
        if isinstance(domain_object, Program):
            refresh_name()
            editor_panel.domain_object_restored(domain_object)

    def refresh_name(self):
        orig_dt = self.stack_model.get_original_composite()
        view_dt = self.stack_model.get_view_composite()
        old_name = orig_dt.name
        new_name = self.function.name
        if old_name == new_name:
            return

        try:
            orig_dt.set_name(new_name)
            if view_dt.name == old_name:
                view_dt.set_name(new_name)

            category_path = orig_dt.category_path
            dt_path = DataTypePath(category_path, old_name)
            self.stack_model.data_type_renamed(self.function.get_program().get_data_type_manager(), dt_path, new_name)
        except InvalidNameException as e:
            Msg.error(self, f"Unexpected Exception: {e.message}", e)

    def domain_object_changed(self, event):
        if not self.is_visible():
            return

        record_count = event.num_records
        for i in range(record_count):
            rec = event.get_change_record(i)
            event_type = rec.event_type
            match event_type:
                case DomainObject.DO_OBJECT_RESTORED:
                    source = event.source
                    if isinstance(source, Program):
                        restored_program = source
                        self.domain_object_restored(restored_program)

                case ChangeManager.DOCR_FUNCTION_REMOVED:
                    func = (Function) ((ProgramChangeRecord) rec).object
                    if func == self.function:
                        self.dispose()
                        tool.set_status_info(f"Stack Editor was closed for {self.name}")

                case _:
                    pass

    def reload_function(self):
        if not self.stack_model.has_changes():
            self.stack_model.load(self.function)
        else:
            self.stack_model.stack_changed_excternally(True)
            editor_panel.set_status("Stack may have been changed externally--data may be stale.")

    @staticmethod
    def in_current_function(record):
        match record:
            case ProgramChangeRecord() as program_change_record:
                affected_value = program_change_record.object
                if isinstance(affected_value, Symbol):
                    address = (Symbol) affected_value).address
                    return address.is_variable_address()

                elif isinstance(affected_value, Function):
                    changed_entry = ((Function) affected_value).entry_point
                    return changed_entry == self.function.entry_point

            case _:
                return False


class ApplyAction:
    def __init__(self, provider):
        self.provider = provider

    # ... other methods ...


# And so on for the rest of the classes and actions.
