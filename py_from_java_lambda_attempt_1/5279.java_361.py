Here is the translation of the Java interface `Demangled` into a Python class:

```Python
class Demangled:
    def __init__(self):
        self._mangled_string = None
        self._original_demangled = None
        self._name = None
        self._namespace = None

    @property
    def mangled_string(self):
        return self._mangled_string

    @mangled_string.setter
    def mangled_string(self, value):
        self._mangled_string = value

    @property
    def original_demangled(self):
        return self._original_demangled

    @original_demangled.setter
    def original_demangled(self, value):
        self._original_demangled = value

    def get_mangled_string(self):
        """Returns the original mangled string"""
        return self.mangled_string

    def get_original_demangled(self):
        """Returns the original demangled string returned by the demangling service"""
        return self.original_demangled

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    def get_name(self):
        """Returns the demangled name of this object. NOTE: unsupported symbol characters, like whitespace, will be converted to an underscore"""
        if not self.name:
            return ""
        else:
            return self.name.replace(" ", "_")

    @property
    def namespace(self):
        return self._namespace

    @namespace.setter
    def namespace(self, value):
        self._namespace = value

    def get_namespace(self):
        """Returns the namespace containing this demangled object"""
        return self.namespace

    def set_namespace(self, ns):
        """Sets the namespace of this demangled object"""
        self.namespace = ns

    @property
    def namespace_string(self):
        if not self.name:
            return ""
        else:
            return f"{self.get_name()}"

    def get_namespace_string(self):
        """Returns a representation of this object as fully-qualified namespace. The value returned here may have had some special characters replaced, such as '  ' replaced with '_' and '::' replaced with '--'"""
        if not self.name:
            return ""
        else:
            return f"{self.get_name()}"

    @property
    def namespace_name(self):
        """Returns this object's namespace name without the fully-qualified parent path. The value returned here may have had some special characters replaced, such as '  ' replaced with '_' and '::' replaced with '--'"""
        if not self.name:
            return ""
        else:
            return f"{self.get_name()}"

    def get_signature(self):
        """Generates a complete representation of this object to include all know attributes of this object """
        # This method should be implemented based on the actual requirements
        pass

# Example usage:

d = Demangled()
print(d.get_mangled_string())  # Returns None, as it's not set yet.
```

Please note that Python does not have direct equivalent for Java interfaces. Instead, we can use abstract classes or protocols to achieve similar functionality. In this case, I've used a regular class with properties and methods to mimic the behavior of the `Demangled` interface in Java.