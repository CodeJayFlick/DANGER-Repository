class DecompilerController:
    def __init__(self, handler, options, clipboard):
        self.cache_size = options.get_cache_size()
        self.callback_handler = handler
        self.decompiler_cache = self.build_cache()
        self.decompiler_mgr = DecompilerManager(self, options)
        self.decompiler_panel = DecompilerPanel(self, options, clipboard, self.decompiler_mgr.get_task_monitor_component())
        self.decompiler_panel.set_hover_mode(True)

    def get_decompiler_panel(self):
        return self.decompiler_panel

    # Methods called by the provider
    def dispose(self):
        self.clear_cache()
        self.decompiler_mgr.dispose()
        self.decompiler_panel.dispose()

    def clear(self):
        self.current_selection = None
        self.decompiler_mgr.cancel_all()
        self.set_decompile_data(EmptyDecompileData("No Function"))

    def display(self, program, location, viewer_position):
        if not self.decompiler_mgr.is_busy() and self.decompiler_panel.contains_location(location):
            self.decompiler_panel.set_location(location, viewer_position)
            return
        if self.load_from_cache(program, location, viewer_position):
            self.decompiler_panel.set_location(location, viewer_position)
            return
        self.decompiler_mgr.decompile(program, location, viewer_position, None, False)

    def load_from_cache(self, program, location, viewer_position):
        function_manager = program.get_function_manager()
        function = function_manager.get_function_containing(location.address)
        if function is None:  # cache can't handle null keys
            return False

        results = self.decompiler_cache.get_if_present(function)

        if results is None:
            return False

        # cancel pending decompile tasks; previous requests shouldn't overwrite the latest request
        self.decompiler_mgr.cancel_all()
        self.set_decompile_data(DecompileData(program, function, location, results, None, None, viewer_position))

        return True

    def set_selection(self, selection):
        self.decompiler_panel.set_selection(selection)

    # Methods called by DecompilerManager
    def set_decomple_data(self, decompile_data):
        self.update_cache(decompile_data)
        self.current_decompile_data = decompile_data
        self.decompiler_panel.set_decompile_data(decompile_data)
        self.decompiler_panel.set_selection(self.current_selection)
        self.callback_handler.decompile_data_changed(decompile_data)

    def update_cache(self, decompile_data):
        function = decompile_data.get_function()
        results = decompile_data.get_decompile_results()

        if function is not None and results is not None and results.is_completed():
            self.decompiler_cache.put(function, results)

    # Methods called by actions and other miscellaneous classes
    def do_when_not_busy(self, callback):
        self.callback_handler.do_when_not_busy(callback)

    def refresh_display(self, program, location, debug_file):
        self.clear_cache()
        self.decompiler_mgr.decompile(program, location, None, debug_file, True)

    # ... rest of the methods

class EmptyDecompileData:
    def __init__(self, message):
        self.message = message
