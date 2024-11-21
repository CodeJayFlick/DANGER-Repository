Here is a translation of the Java code into Python:

```Python
class CondIsPluginEnabled:
    def __init__(self):
        self.plugins = None
        self.pattern = 0

    @staticmethod
    def register_condition():
        Skript.register_condition(CondIsPluginEnabled, "plugin[es] %strings% (is|are) enabled", 
                                 "plugin[es] %strings% (is|are)(n't| not) enabled", 
                                 "plugin[es] %strings% (is|are) disabled")

    def init(self, exprs, matched_pattern):
        self.plugins = exprs[0]
        self.pattern = matched_pattern
        return True

    def check(self, e):
        if isinstance(e, Event):
            plugins_list = [p for p in str(self.plugins).split() if p != '']
            result = all(Bukkit.get_plugin_manager().get_plugin(plugin) and Bukkit.get_plugin_manager().get_plugin(plugin).isEnabled() 
                         for plugin in plugins_list)
            return {
                1: not result,
                2: result,
                0: result
            }.get(self.pattern, None)

    def __str__(self):
        if self.plugins.is_single():
            plural = " is"
        else:
            plural = " are"

        pattern_strs = [" enabled", " not enabled", " disabled"]
        return f"plugin{'s' if len(str(self.plugins).split()) > 1 else ''}{plural}{pattern_strs[self.pattern]}"
```

Please note that this translation does not include the Java-specific parts like annotations, static blocks or imports.