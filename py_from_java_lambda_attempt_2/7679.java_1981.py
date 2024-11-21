Here is the translation of the given Java code into Python:

```Python
class GnuDemanglerOptions:
    GNU_DEMANGLER_V2_24 = "demangler_gnu_v2_24"
    GNU_DEMANGLER_V2_33_1 = "demangler_gnu_v2_33_1"
    DEFAULT = GNU_DEMANGLER_V2_33_1

    def __init__(self, format=GnuDemanglerFormat.AUTO):
        self.format = format
        if not isinstance(format, GnuDemanglerFormat) or not format.isAvailable():
            raise ValueError("Invalid demangling format")

    @classmethod
    def with_demangler_format(cls, demangler_format, use_deprecated=False):
        return cls(demangler_format)

class GnuDemanglerFormat:
    AUTO = "auto"
    V2_24 = "v2.24"
    V2_33_1 = "v2.33.1"

    def __init__(self, name):
        self.name = name

    @classmethod
    def get_format(cls):
        return cls.AUTO

class DemanglerOptions:
    pass


def main():
    options = GnuDemanglerOptions()
    print(options.get_demangler_name())

if __name__ == "__main__":
    main()

```

Note: The above Python code does not include the `GnuDemanglerFormat` and `DemanglerOptions` classes as they are part of the original Java code.