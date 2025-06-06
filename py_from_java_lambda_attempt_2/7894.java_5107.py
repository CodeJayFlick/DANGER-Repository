Here is the translation of the given Java code into equivalent Python:

```Python
class MDFragmentName:
    def __init__(self):
        pass  # Assuming this class exists in your project


class MDObjectC(MDObject):  # Assuming MDObject class also exists in your project
    def __init__(self, dmang):
        super().__init__(dmang)
        self.name = MDFragmentName()

    def insert(self, builder: str) -> None:
        builder += str(self.name)

    def parse_internal(self) -> None:
        try:
            self.name.parse()
        except MDException as e:
            raise
```

Please note that this translation assumes the existence of `MDFragmentName` and `MDObject` classes in your project.