Here is the equivalent Python code:

```Python
class GzfExporter:
    EXTENSION = "gzf"
    SUFFIX = "." + EXTENSION
    NAME = "Ghidra Zip File"

    def __init__(self):
        super().__init__(NAME, EXTENSION)

    def __eq__(self, obj):
        return isinstance(obj, self.__class__)

    def export(self, file_path: str, domain_obj, addr_set_view, monitor=None) -> bool:
        try:
            if os.path.exists(file_path):
                os.remove(file_path)
            with open(file_path, "wb") as f:
                domain_obj.save_to_packed_file(f, monitor)
        except Exception as e:
            print("Unexpected exception exporting file:", str(e))
            return False
        return True

    def get_options(self) -> list:
        # No options for this exporter
        return []

    def set_options(self, options: list):
        pass  # no options to set

    def supports_partial_export(self) -> bool:
        return False


if __name__ == "__main__":
    gzf = GzfExporter()
```

Note that Python does not have direct equivalents for Java's `File`, `DomainObjectService`, and other classes. I've replaced them with equivalent constructs in the above code, such as using the built-in `os` module to work with files.