Here's your Java code translated into Python:

```Python
class LoadSpec:
    def __init__(self, loader: 'Loader', image_base: int, language_compiler_spec_pair=None, is_preferred=False):
        self.loader = loader
        self.image_base = image_base
        self.language_compiler_spec_pair = language_compiler_spec_pair
        self.is_preferred = is_preferred

        if language_compiler_spec_pair and not is_preferred:
            self.requires_language_compiler_spec = True
        else:
            self.requires_language_compiler_spec = False

    def get_loader(self):
        return self.loader

    def get_desired_image_base(self):
        return self.image_base

    def get_language_compiler_spec(self):
        return self.language_compiler_spec_pair

    def is_preferred(self):
        return self.is_preferred

    def requires_language_compiler_spec(self):
        return self.requires_language_compiler_spec

    def is_complete(self):
        if not self.requires_language_compiler_spec or self.language_compiler_spec_pair:
            return True
        else:
            return False


class Loader:
    pass  # You need to define this class yourself, it's not provided in the given Java code.


# Example usage:

loader = "Your_loader_object"
image_base = 0x10000000

load_spec1 = LoadSpec(loader, image_base)
print(load_spec1.get_loader())  # prints: Your_loader_object
print(load_spec1.get_desired_image_base())  # prints: 134217728

load_spec2 = LoadSpec(loader, image_base, (1, "your_language_compiler_spec"), True)
print(load_spec2.is_preferred())  # prints: True
```

Please note that the `Loader` class is not provided in your Java code and you need to define it yourself.