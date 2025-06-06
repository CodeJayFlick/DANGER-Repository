Here is the translation of the given Java code into Python:

```Python
class ExternalReferencePluginEvent:
    NAME = "ExternalReference"

    def __init__(self, src: str, external_loc: 'ExternalLocation', program_path: str):
        self.src = src
        self.name = self.NAME
        self.external_location = external_loc
        self.program_path = program_path

    @property
    def get_external_location(self) -> 'ExternalLocation':
        return self.external_location

    @property
    def get_program_path(self) -> str:
        return self.program_path


class ExternalLocation:
    pass  # You would need to define this class further based on your requirements.


# Example usage:

if __name__ == "__main__":
    external_loc = ExternalLocation()  # Replace with actual implementation.
    program_path = "path_to_your_program_file"
    
    event = ExternalReferencePluginEvent("source", external_loc, program_path)
    
    print(event.get_external_location())
    print(event.get_program_path())

```

Please note that Python does not have direct equivalent of Java's `public` and `private`. In Python, everything is public by default. If you want to restrict access to certain attributes or methods, you can use underscore prefix (e.g., `_program_path`) which is a convention in Python for indicating internal implementation details.

Also note that I've used type hints (`str`, `'ExternalLocation'`) and properties (`@property`) as they are commonly used in modern Python code.