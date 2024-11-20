Here is the translation of the Java code into Python:

```Python
class PluginConfigurationModel:
    def __init__(self, tool):
        self.tool = tool
        self.listener = None  # dummy listener for now
        self.plugin_class_manager = tool.get_plugin_class_manager()
        self.init_loaded_plugins()

    def init_loaded_plugins(self):
        self.loaded_plugins_map.clear()
        self.plugins_with_dependencies_set.clear()
        loaded_plugins = self.tool.get_managed_plugins()
        for plugin in loaded_plugins:
            description = self.get_plugin_description(plugin)
            self.loaded_plugins_map[description] = plugin
            self.find_dependencies(plugin, loaded_plugins)

    def find_dependencies(self, plugin, plugins):
        for p in plugins:
            if p.depends_upon(plugin):
                self.plugins_with_dependencies_set.add(description)

    def get_plugin_description(self, plugin):
        return self.plugin_class_manager.get_plugin_description(plugin.__class__.__name__)

    def is_loaded(self, description):
        return description in self.loaded_plugins_map

    def add_plugin(self, description):
        try:
            self.tool.add_plugin(description)
        except PluginException as e:
            print(f"Error loading plugin: {e}")
        self.init_loaded_plugins()
        self.listener.state_changed(None)

    def remove_all_plugins(self, package):
        descriptions = self.get_plugin_descriptions(package)
        loaded_plugins = [self.loaded_plugins_map[description] for description in descriptions if is_loaded(description)]
        self.tool.remove_plugins(loaded_plugins)
        self.init_loaded_plugins()
        self.listener.state_changed(None)

    def add_all_plugins(self, package):
        try:
            self.tool.add_plugins([description.get_plugin_class().get_name() for description in self.get_plugin_descriptions(package)])
        except PluginException as e:
            print(f"Error loading plugin(s): {e}")
        self.init_loaded_plugins()
        self.listener.state_changed(None)

    def remove_plugin(self, description):
        if is_loaded(description):
            self.tool.remove_plugins([self.loaded_plugins_map[description]])
        self.init_loaded_plugins()
        self.listener.state_changed(None)

    def has_dependencies(self, description):
        return description in self.plugins_with_dependencies_set

    def get_actions_for_plugin(self, description):
        if not is_loaded(description):
            return set()
        return KeyBindingUtils.get_key_binding_actions_for_owner(self.tool, description)

    def get_dependencies(self, pd):
        plugin = self.loaded_plugins_map[pd]
        return [p for p in self.tool.get_managed_plugins() if p.depends_upon(plugin)]

    @property
    def unstable_package(self):
        return self._unstable_package

    @unstable_package.setter
    def unstable_package(self, value):
        self._unstable_package = value

    def get_plugin_packages(self):
        packages_with_stable_plugins = []
        for package in self.plugin_class_manager.get_plugin_packages():
            if not self.unstable_package == package and len(self.get_plugin_descriptions(package)) > 0:
                packages_with_stable_plugins.append(package)
        if self.unstable_package is not None:
            packages_with_stable_plugins.append(self.unstable_package)
        return packages_with_stable_plugins

    def get_plugin_descriptions(self, package):
        if package == self.unstable_package:
            return [description for description in self.plugin_class_manager.get_non_released_plugin_descriptions()]
        else:
            return self.plugin_class_manager.get_released_plugin_descriptions(package)

    def get_all_plugin_descriptions(self):
        return self.plugin_class_manager.get_all_plugin_descriptions()

class PluginPackageState:
    NO_PLUGINS_LOADED = 0
    SOME_PLUGINS_LOADED = 1
    ALL_PLUGINS_LOADED = 2

# Initialize the unstable package
unstable_package = None
```

Please note that Python does not have direct equivalent of Java's `HashMap` and `HashSet`. We use built-in dictionary (`{}`) for mapping and set operations. Also, we don't need to manually clear the dictionaries as they automatically handle this when you assign a new value or delete an existing one.

Also, please be aware that Python does not have direct equivalent of Java's `PluginException` class. You can use built-in exceptions like `ValueError`, `TypeError`, etc., depending on your needs.