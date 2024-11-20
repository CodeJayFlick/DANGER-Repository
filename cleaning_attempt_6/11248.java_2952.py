class PluginInfo:
    def __init__(self):
        self.status = None  # Replace with actual implementation
        self.package_name = None  # Replace with actual implementation
        self.category = None  # Replace with actual implementation
        self.short_description = None  # Replace with actual implementation
        self.description = None  # Replace with actual implementation
        self.is_slow_installation = False

    def status(self):
        return self.status

    @property
    def package_name(self):
        return self.package_name

    @package_name.setter
    def package_name(self, value):
        self.package_name = value

    @property
    def category(self):
        return self.category

    @category.setter
    def category(self, value):
        self.category = value

    @property
    def short_description(self):
        return self.short_description

    @short_description.setter
    def short_description(self, value):
        self.short_description = value

    @property
    def description(self):
        return self.description

    @description.setter
    def description(self, value):
        self.description = value

    @property
    def is_slow_installation(self):
        return self.is_slow_installation

    @is_slow_installation.setter
    def is_slow_installation(self, value):
        if isinstance(value, bool):
            self.is_slow_installation = value
        else:
            raise ValueError("Expected a boolean value")

    def events_consumed(self):
        # Replace with actual implementation or default to empty list
        return []

    @property
    def services_required(self):
        return []  # Replace with actual implementation

    @services_required.setter
    def services_required(self, value):
        if isinstance(value, (list, tuple)):
            self.services_required = [cls for cls in value]
        else:
            raise ValueError("Expected a list or tuple of classes")

    @property
    def services_provided(self):
        return []  # Replace with actual implementation

    @services_provided.setter
    def services_provided(self, value):
        if isinstance(value, (list, tuple)):
            self.services_provided = [cls for cls in value]
        else:
            raise ValueError("Expected a list or tuple of classes")
