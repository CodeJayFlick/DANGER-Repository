class PluginPackage:
    CORE_PRIORITY = 0
    FEATURE_PRIORITY = 4
    MISCELLANIOUS_PRIORITY = 6
    DEVELOPER_PRIORITY = 8
    EXAMPLES_PRIORITY = 10
    EXPERIMENTAL_PRIORITY = 12

    package_map = None

    def __new__(cls, name: str, icon=None, description="", priority=FEATURE_PRIORITY):
        if not hasattr(cls, 'package_map'):
            cls.package_map = {}
            for subclass in PluginPackage.__subclasses__():
                try:
                    instance = subclass()
                    name_lower = instance.name.lower()
                    if name_lower in cls.package_map:
                        print(f"Plugin package already exists with the name {name_lower}")
                    else:
                        cls.package_map[name_lower] = instance
                except Exception as e:
                    print(f"Could not instantiate {subclass.__name__}: {e}")

        return super().__new__(cls)

    @classmethod
    def get_plugin_package(cls, package_name: str):
        if cls.package_map is None:
            cls.package_map = {}
            for subclass in PluginPackage.__subclasses__():
                try:
                    instance = subclass()
                    name_lower = instance.name.lower()
                    cls.package_map[name_lower] = instance
                except Exception as e:
                    print(f"Could not instantiate {subclass.__name__}: {e}")

        package_name = package_name.lower()

        if package_name in cls.package_map:
            return cls.package_map[package_name]
        else:
            Msg.warn(PluginPackage, f"Can't find plugin package for {package_name}! Creating stub...")
            return cls.get_plugin_package(MiscellaneousPluginPackage.NAME)

    def __init__(self, name: str, icon=None, description="", priority=0):
        self.name = name
        self.icon = icon
        self.description = description
        self.priority = priority

    @property
    def name(self) -> str:
        return self._name

    @name.setter
    def name(self, value: str):
        self._name = value

    @property
    def icon(self):
        return self._icon

    @icon.setter
    def icon(self, value):
        self._icon = value

    @property
    def description(self) -> str:
        return self._description

    @description.setter
    def description(self, value: str):
        self._description = value

    @property
    def priority(self) -> int:
        return self._priority

    @priority.setter
    def priority(self, value: int):
        self._priority = value

    def __lt__(self, other):
        if self.priority == other.priority:
            return self.name < other.name
        else:
            return self.priority - other.priority < 0

    def isfullyAddable(self) -> bool:
        return True


class MiscellaneousPluginPackage(PluginPackage):

    NAME = "Miscellaneous"

    def __init__(self):
        super().__init__(name=self.NAME, icon=None, description="", priority=MiscellaneousPluginPackage.MISCELLANIOUS_PRIORITY)
