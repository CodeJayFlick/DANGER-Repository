Here is a translation of the Java code into equivalent Python:

```Python
class DebuggerObjectsPlugin:
    def __init__(self):
        self.providers = []
        self.first_pass = True
        self.active_program = None
        self.copied_save_state = SaveState()

    @property
    def interpreter_service(self):
        return self._interpreter_service

    @interpreter_service.setter
    def interpreter_service(self, value):
        if self._interpreter_service is not None:
            self._interpreter_service.remove_models_changed_listener(self)
        self._interpreter_service = value
        if self._interpreter_service is not None:
            self._interpreter_service.add_models_changed_listener(self)

    @property
    def model_service(self):
        return self._model_service

    @model_service.setter
    def model_service(self, value):
        if self._model_service is not None:
            self._model_service.remove_models_changed_listener(self)
        self._model_service = value
        if self._model_service is not None:
            self._model_service.add_models_changed_listener(self)

    def add_provider(self, provider):
        self.providers.append(provider)

    def process_event(self, event):
        super().process_event(event)
        # handle events

    def fire_object_updated(self, object_container):
        event = ObjectUpdatedEvent(object_container)
        r = lambda: self.fire_plugin_event(event)
        SwingUtilities.invokeLater(r)

    def show_console(self, interpreter):
        Swing.run_if_swing_or_run_later(lambda: self.interpreter_service.show_console(interpreter))

    class ProviderRunnable:
        def __init__(self, plugin, model):
            self.plugin = plugin
            self.model = model

        def run(self):
            try:
                self.plugin.write_config_state(self.plugin.copied_save_state)
                container = ObjectContainer(None, None)
                provider = DebuggerObjectsProvider(
                    self.plugin,
                    self.model,
                    container,
                    True
                )
                provider.read_config_state(self.plugin.copied_save_state)
                container.propagate_provider(provider)
                provider.update(container)
                provider.refresh()
            except Exception as e:
                print(str(e))

    def element_added(self, model):
        top = self.providers[-1]
        existing_model = top.get_model()
        if existing_model is None:
            top.set_model(model)
        else:
            SwingUtilities.invokeLater(
                ProviderRunnable(self, model)
            )

    def element_removed(self, model):
        to_remove = []
        for p in self.providers:
            if model == p.get_model():
                tool.remove_component_provider(p)
                to_remove.append(p)
        for p in to_remove:
            self.providers.remove(p)
        if len(self.providers) == 0:
            Swing.run_if_swing_or_run_later(lambda: self.init())

    def element_modified(self, model):
        print(f"modelModified {model}")

    def set_focus(self, object1, focused_object2):
        for p in self.providers:
            p.set_focus(object1, focused_object2)

    @property
    def active_program(self):
        return self._active_program

    @active_program.setter
    def active_program(self, value):
        self._active_program = value

    def write_config_state(self, save_state):
        if len(self.providers) == 0:
            return
        self.providers[0].write_config_state(save_state)

    def read_config_state(self, save_state):
        self.copied_save_state = SaveState(save_state.save_to_xml())
        if len(self.providers) == 0:
            return
        self.providers[0].read_config_state(save_state)
```

Note that this translation is not a direct equivalent of the Java code. Python has different syntax and structure than Java, so some changes were necessary to make it work in Python.