class DecompilerActionContext:
    def __init__(self, provider, function_entry_point, is_decompiling):
        self.function_entry_point = function_entry_point
        self.is_decompiling = is_decompiling

    @property
    def function_entry_point(self):
        return self._function_entry_point

    @property
    def is_decompiling(self):
        return self._is_decompiling

    def get_component_provider(self):
        # This method should be implemented based on the Java code.
        pass

    def get_tool(self):
        # This method should be implemented based on the Java code.
        pass

    @property
    def token_at_cursor(self):
        if not self._token_is_initialized:
            self._token_at_cursor = self.get_decompiler_panel().get_token_at_cursor()
            self._token_is_initialized = True
        return self._token_at_cursor

    def get_decompiler_panel(self):
        # This method should be implemented based on the Java code.
        pass

    @property
    def function(self):
        # This method should be implemented based on the Java code.
        pass

    @property
    def high_function(self):
        # This method should be implemented based on the Java code.
        pass

    @property
    def c_code_model(self):
        # This method should be implemented based on the Java code.
        pass

    def has_real_function(self):
        f = self.function
        return f is not None and isinstance(f, Function)

    def set_status_message(self, msg):
        self.get_component_provider().get_controller().set_status_message(msg)

    def perform_action(self, action_callback):
        if self.is_decompiling:
            print("Decompiler Action Blocked: You cannot perform Decompiler actions while the Decompiler is busy")
            return
        action_callback()

    def check_action_enablement(self, action_boolean_supplier):
        if self.is_decompiling:
            return True
        return action_boolean_supplier.get()
