Here is the translation of the Java code into Python:

```Python
class TableServicePlugin:
    def __init__(self):
        self.update_mgr = None
        self.program_map = {}
        self.dialog_map = {}

    def create_actions(self):
        # Unusual Code: We, as a plugin, don't have any actions. Our transient tables do have 
        # 			     actions. We need a way to have keybindings shared for all the different 
        #				 actions. Further, we need to register them now, not when the transient 
        #               providers are created, as they would only appear in the options at 
        #               that point.
        DeleteTableRowAction.register_dummy(self.get_tool(), self.get_name())

    def dispose(self):
        for program in list(self.program_map.keys()):
            del self.program_map[program]
        if self.update_mgr is not None:
            self.update_mgr.dispose()
        super().dispose()

    def process_event(self, event):
        if isinstance(event, ProgramClosedPluginEvent):
            program = (event).get_program()
            self.close_all_queries(program)
        else:
            super().process_event(event)

    def close_all_queries(self, program):
        self.clear_table_component_providers(program)
        self.clear_table_dialogs(program)

    def clear_table_component_providers(self, program):
        providers_list = self.program_map.get(program)
        if providers_list is not None:
            for provider in list(providers_list):
                provider.close_component()
            del self.program_map[program]

    def clear_table_dialogs(self, program):
        dialogs_list = self.dialog_map.get(program)
        if dialogs_list is not None:
            for dialog in list(dialogs_list):
                dialog.close()
            del self.dialog_map[program]

    def show_table(self, title, table_type_name, model, window_submenu, navigatable):
        goto_service = self.get_tool().get_service(GoToService)
        program = model.get_program()

        if goto_service is not None and navigatable is None:
            navigatable = goto_service.get_default_navigatable()
        
        provider = TableComponentProvider(self, title, table_type_name, 
                                          model, program.domain_file.name, goto_service, window_submenu, navigatable)
        self.add_provider(program, provider)

    def show_table_with_markers(self, title, table_type_name, model, marker_color, marker_icon, 
                               window_submenu, navigatable):
        goto_service = self.get_tool().get_service(GoToService)
        program = model.get_program()

        if goto_service is not None and navigatable is None:
            navigatable = goto_service.get_default_navigatable()
        
        provider = TableComponentProvider(self, title, table_type_name, 
                                          model, program.domain_file.name, goto_service, marker_color, 
                                          marker_icon, window_submenu, navigatable)
        self.add_provider(program, provider)

    def add_provider(self, program, provider):
        providers_list = self.program_map.get(program)
        if providers_list is None:
            providers_list = []
            self.program_map[program] = providers_list
        providers_list.append(provider)

    def remove(self, provider):
        for program in list(self.program_map.keys()):
            providers_list = self.program_map.get(program)
            if providers_list is not None and providers_list.remove(provider):
                if len(providers_list) == 0:
                    del self.program_map[program]

    def remove_dialog(self, dialog):
        for program in list(self.dialog_map.keys()):
            dialogs_list = self.dialog_map.get(program)
            if dialogs_list is not None and dialogs_list.remove(dialog):
                if len(dialogs_list) == 0:
                    del self.dialog_map[program]

    def domain_object_changed(self, ev):
        self.update_mgr.update()

    def get_managed_components(self):
        providers_list = list(self.program_map.values())
        return [provider for sublist in providers_list for provider in sublist]

    def get_program(self):
        # This method is not implemented
        pass

    def update_providers(self):
        providers_list = self.get_providers()
        for i, provider in enumerate(providers_list):
            provider.refresh()

    def create_table_chooser_dialog(self, executor, program, title, navigatable):
        return self.create_table_chooser_dialog(executor, program, title, navigatable, False)

    def create_table_chooser_dialog(self, executor, program, title, navigatable, is_modal):
        goto_service = self.get_tool().get_service(GoToService)
        
        if goto_service is not None and navigatable is None:
            navigatable = goto_service.get_default_navigatable()
        
        nav = navigatable
        dialog = Swing.run_now(lambda: MyTableChooserDialog(self, executor, program, title, nav, is_modal))
        
        dialogs_list = self.dialog_map.setdefault(program, [])
        dialogs_list.append(dialog)
        return dialog

    def get_tool(self):
        # This method is not implemented
        pass

    def get_name(self):
        # This method is not implemented
        pass

class TableComponentProvider:
    def __init__(self, table_service_plugin, title, table_type_name, model, program_domain_file_name, 
                 goto_service, window_submenu, navigatable):
        self.table_service_plugin = table_service_plugin
        self.title = title
        self.table_type_name = table_type_name
        self.model = model
        self.program_domain_file_name = program_domain_file_name
        self.goto_service = goto_service
        self.window_submenu = window_submenu
        self.navigatable = navigatable

    def close_component(self):
        # This method is not implemented
        pass

class MyTableChooserDialog:
    def __init__(self, table_service_plugin, executor, program, title, navigatable, is_modal):
        self.table_service_plugin = table_service_plugin
        self.executor = executor
        self.program = program
        self.title = title
        self.navigatable = navigatable
        self.is_modal = is_modal

    def close(self):
        # This method is not implemented
        pass