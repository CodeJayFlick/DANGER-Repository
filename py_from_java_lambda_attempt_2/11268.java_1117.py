Here is the equivalent Python code:

```
class PluginStatus:
    RELEASED = ("Released (Tested and Documented)")
    STABLE = ("Useable, but not fully tested or documented")
    UNSTABLE = ("This plugin is under Development. Use of this plugin is not recommended.")
    HIDDEN = ("This plugin is not available via the plugin configuration GUI")

class PluginStatusEnum:
    def __init__(self):
        self.description_map = {
            "RELEASED": PluginStatus.RELEASED,
            "STABLE": PluginStatus.STABLE,
            "UNSTABLE": PluginStatus.UNSTABLE,
            "HIDDEN": PluginStatus.HIDDEN
        }

    def get_description(self, status):
        return self.description_map.get(status)

# Usage:
plugin_status = PluginStatusEnum()
print(plugin_status.get_description("RELEASED"))  # Output: Released (Tested and Documented)
```

Note that Python does not have an equivalent to Java's `enum` keyword. Instead, we define a class with static attributes for each status value. We also create another class (`PluginStatusEnum`) to map the string values back to their corresponding descriptions.