Here's your Java code translated into Python:

```Python
class BundleStatus:
    def __init__(self, bundle_file, enabled, read_only, location):
        self.file = bundle_file
        self.type = GhidraBundle.get_type(bundle_file)
        self.location = location
        self.enabled = enabled
        self.read_only = read_only

    def compare_to(self, other):
        return str(self.path).compareTo(str(other.path))

    @property
    def is_enabled(self):
        return self.enabled

    @is_enabled.setter
    def set_enabled(self, value):
        self.enabled = value

    @property
    def is_read_only(self):
        return self.read_only

    @read_only.setter
    def set_read_only(self, value):
        self.read_only = value

    @property
    def type_(self):
        return self.type

    @type_.setter
    def set_type_(self, value):
        self.type_ = value

    @property
    def is_active(self):
        return self.active

    @is_active.setter
    def set_active(self, value):
        self.active = value

    @property
    def summary(self):
        return self.summary_

    @summary.setter
    def set_summary_(self, value):
        self.summary_ = value

    @property
    def file_exists(self):
        return self.file.exists()

    @property
    def path(self):
        return str(self.file)

    @property
    def location_identifier(self):
        return self.location

    def set_busy(self, is_busy):
        self.busy = is_busy

    @property
    def is_busy(self):
        return self.busy


class GhidraBundle:
    TYPE = None  # Replace with your actual type definition

    @staticmethod
    def get_type(bundle_file):
        pass  # Implement this method to define the bundle type based on the file
```

Please note that I've used Python's property decorator (`@property`) and setter methods to mimic Java's getter and setter methods.