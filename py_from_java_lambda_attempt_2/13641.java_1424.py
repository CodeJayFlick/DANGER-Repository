Here is the translation of the given Java code into Python:

```Python
class SkeletonLoader:
    def __init__(self):
        pass

    def get_name(self):
        return "My loader"

    def find_supported_load_specs(self, provider):
        load_specs = []
        # TODO: Examine the bytes in 'provider' to determine if this loader can load it.  If it 
        # can load it, return the appropriate load specifications.
        return load_specs

    def load(self, provider, load_spec, options, program, monitor, log):
        # TODO: Load the bytes from 'provider' into the 'program'.
        pass

    def get_default_options(self, provider, load_spec, domain_object, is_load_into_program):
        list = super().get_default_options(provider, load_spec, domain_object, is_load_into_program)
        # TODO: If this loader has custom options, add them to 'list'
        option = {"name": "Option name goes here", "value": "Default option value goes here"}
        list.append(option)
        return list

    def validate_options(self, provider, load_spec, options, program):
        # TODO: If this loader has custom options, validate them here.  Not all options require
        # validation.
        return super().validate_options(provider, load_spec, options, program)

class LoadSpec:
    pass

class Option:
    def __init__(self, name, value):
        self.name = name
        self.value = value

# Usage example:

skeleton_loader = SkeletonLoader()
print(skeleton_loader.get_name())
```

Please note that this is a direct translation of the given Java code into Python. However, it may not be exactly equivalent to the original Java code because some features like exception handling and multithreading are handled differently in Python than they are in Java.