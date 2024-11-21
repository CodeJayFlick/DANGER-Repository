class InterpreterComponentProvider:
    def __init__(self, plugin, interpreter, visible):
        self.panel = InterpreterPanel(plugin.get_tool(), interpreter)
        self.interpreter = interpreter
        self.first_activation_callbacks = []

        set_help_location(HelpLocation(self.name, "interpreter"))

        add_to_tool()
        create_actions()

        icon = interpreter.get_icon() or ResourceManager.load_image("images/monitor.png")
        self.set_icon(icon)

        self.setVisible(visible)

    def create_actions(self):
        clear_action = DockingAction("Clear Interpreter", self.name)
        clear_action.setDescription("Clear Interpreter")
        clear_action.setToolBarData(ResourceManager.load_image("images/erase16.png"), None)
        clear_action.setEnabled(True)

        add_local_action(clear_action)

    def set_transient(self):
        dispose_action = DockingAction("Remove Interpreter", self.name)
        dispose_action.addActionListener(lambda context: self.dispose())
        dispose_action.setDescription("Remove interpreter from tool")
        dispose_action.setToolBarData(Icons.STOP_ICON, None)
        dispose_action.setEnabled(True)

        add_local_action(dispose_action)

    def get_window_submenu_name(self):
        return self.interpreter.getTitle()

    def getTitle(self):
        return self.interpreter.getTitle()

    def get_subtitle(self):
        return "Interpreter"

    def get_component(self):
        return self.panel

    def clear(self):
        self.panel.clear()

    def get_stdin(self):
        return self.panel.get_stdin()

    def get_stdout(self):
        return self.panel.get_stdout()

    def get_stderr(self):
        return self.panel.get_stderr()

    def get_out_writer(self):
        return self.panel.get_out_writer()

    def get_err_writer(self):
        return self.panel.get_err_writer()

    def get_prompt(self):
        return self.panel.get_prompt()

    def set_prompt(self, prompt):
        self.panel.set_prompt(prompt)

    def dispose(self):
        remove_from_tool()
        self.panel.dispose()

    def component_activated(self):
        # Since we only care about the first activation, clear the list of callbacks so future 
        # activations don't trigger anything.  First save them off to a local list so when we
        # process them we aren't affected by concurrent modification due to reentrance.
        callbacks = self.first_activation_callbacks.copy()
        self.first_activation_callbacks.clear()

        # Call the callbacks
        for callback in callbacks:
            callback.call()

    def add_first_activation_callback(self, activation_callback):
        self.first_activation_callbacks.append(activation_callback)

    def is_input_permitted(self):
        return self.panel.is_input_permitted()

    def set_input_permitted(self, permitted):
        self.panel.set_input_permitted(permitted)

    def show(self):
        tool.show_component_provider(self, True)

    def update_title(self):
        tool.update_title(self)
