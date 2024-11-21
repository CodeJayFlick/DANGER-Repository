Here is the translation of the Java code into Python:

```Python
class DebuggerWorkflowServicePlugin:
    def __init__(self, tool):
        self.tool = tool
        # Auto-service wiring (not applicable in Python)
        # options = tool.get_options("workflow")
        # options.add_listener(self)

    def init(self):
        super().init()
        ClassSearcher.add_change_listener(self.bots_changed)
        self.refresh_bots()

    def dispose(self):
        ClassSearcher.remove_change_listener(self.bots_changed)
        for listener in track_stuff_listeners_by_tool.values():
            listener.dispose()
        track_stuff_listeners_by_tool.clear()

    def dispatch(self, event):
        with lock(all_bots):
            for bot in all_bots:
                if bot.is_enabled():
                    event.accept(bot)

    def bots_changed(self, change_event):
        self.refresh_bots()

    def refresh_bots(self):
        with lock(all_bots):
            removed = list(set(all_bots) - set(ClassSearcher.get_instances(DebuggerBot)))
            added = list(set(all_bots) & set(ClassSearcher.get_instances(DebuggerBot)))

            for bot in removed:
                options.remove_option(bot.description)
                try:
                    if bot.is_enabled():
                        bot.disable()
                except Exception as e:
                    Msg.error(self, f"Failed to disable debugger bot: {bot}", e)

            for bot in added:
                options.register_option(bot.description, OptionType.BOOLEAN_TYPE,
                                         bot.is_enabled_by_default(), bot.get_help_location(),
                                         bot.get_details())
                try:
                    if not bot.is_enabled():
                        bot.enable()
                except Exception as e:
                    Msg.error(self, f"Failed to enable debugger bot: {bot}", e)

    def options_changed(self, opts, option_name, old_value, new_value):
        # Not the most efficient, but there are few, and this should occur infrequently
        if SystemUtilities.is_in_testing_mode():
            return

        with lock(all_bots):
            for bot in all_bots:
                if not bot.description == option_name:
                    continue
                enabled = bool(new_value)
                if bot.is_enabled() != enabled:
                    try:
                        bot.set_enabled(self, enabled)
                    except Exception as e:
                        Msg.error(self, f"Failed to set debugger bot: {bot}", e)

    def plugin_tool_added(self, tool):
        track_tool_events(tool)

    def plugin_tool_removed(self, tool):
        untrack_tool_events(tool)

    def get_proxying_plugin_tools(self):
        return list(track_stuff_listeners_by_tool.keys())

    @property
    def model_service(self):
        # Auto-service wiring (not applicable in Python)
        pass

    @model_service.setter
    def set_model_service(self, value):
        if self.model_service is not None:
            self.model_service.remove_models_changed_listener(self.models_changed_listener)

        self.model_service = value

        if self.model_service is not None:
            self.model_service.add_models_changed_listener(self.models_changed_listener)
        # TODO: Invoke models removed/added

    @property
    def all_bots(self):
        return set(all_bots)

    @property
    def enabled_bots(self):
        return {bot for bot in all_bots if bot.is_enabled()}

    @property
    def disabled_bots(self):
        return {bot for bot in all_bots if not bot.is_enabled()}

    def enable_bots(self, bots):
        with lock(all_bots):
            for bot in bots:
                if bot not in all_bots:
                    Msg.error(self, f"Ignoring request to enable non-discoverable bot: {bot}")
                    continue
                if not bot.is_enabled():
                    try:
                        bot.enable()
                    except Exception as e:
                        Msg.error(self, f"Error enabling {bot}", e)

    def disable_bots(self, bots):
        with lock(all_bots):
            for bot in bots:
                if bot not in all_bots:
                    Msg.error(self, f"Ignoring request to disable non-discoverable bot: {bot}")
                    continue
                if bot.is_enabled():
                    try:
                        bot.disable()
                    except Exception as e:
                        Msg.error(self, f"Error disabling {bot}", e)

# Lock for synchronization
lock = threading.Lock()

all_bots = []
track_stuff_listeners_by_tool = {}
models_changed_listener = None

class ForBotsModelsChangeListener:
    def element_added(self, element):
        dispatch(lambda bot: bot.model_added(element))

    def element_removed(self, element):
        dispatch(lambda bot: bot.model_removed(element))
```

Please note that this is a direct translation of the Java code into Python. The original Java code may have some limitations or issues when translated to Python due to differences in language syntax and semantics.