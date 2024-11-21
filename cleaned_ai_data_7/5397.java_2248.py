import xml.etree.ElementTree as ET
from collections import defaultdict

class LibraryHints:
    HINTS_EXT = ".hints"

    def __init__(self):
        self.name_attribute_map = defaultdict(list)
        self.ordinal_attribute_map = defaultdict(list)

    def add(self, ordinal: int, attr: dict) -> None:
        if not self.ordinal_attribute_map[ordinal]:
            self.ordinal_attribute_map[ordinal] = [attr]
        else:
            self.ordinal_attribute_map[ordinal].append(attr)

    def add(self, name: str, attr: dict) -> None:
        if not self.name_attribute_map[name]:
            self.name_attribute_map[name] = [attr]
        else:
            self.name_attribute_map[name].append(attr)

    @staticmethod
    def get_hints_file(library_name: str, size: int) -> tuple:
        filename = library_name.upper()
        return (filename + HINTS_EXT), size

    @classmethod
    def get_library_hints(cls, library_name: str, size: int) -> 'LibraryHints':
        hints = cls()
        file_path, _ = LibraryHints.get_hints_file(library_name, size)
        if file_path and ET.parse(file_path).getroot().tag == "{http://www.w3.org/2000/svg}svg":
            hints.read_library_hints(file_path)
        return hints

    def read_library_hints(self, file_path: str) -> None:
        try:
            tree = ET.parse(file_path)
            root = tree.getroot()
            if root.tag != "{http://www.w3.org/2000/svg}svg" or "LIBRARY_ HINTS" not in [e.text for e in root]:
                raise ValueError("Expected LIBRARY_HINTS document")
            for child in root:
                if child.tag == "{http://www.w3.org/2000/svg}g":
                    self.parse_hint(child)
        except Exception as e:
            print(f"Error occurred while parsing hints file: {file_path}", e)

    def parse_hint(self, element: ET.Element) -> None:
        attr_name = element.get("ATTR")
        value = element.get("VALUE")
        if not (attr_name and value):
            raise ValueError("HINT element requires both ATTR and VALUE attributes")
        ord_str = element.get("ORDINAL")
        if ord_str:
            try:
                ordinal = int(ord_str)
                self.add(ordinal, {"name": attr_name, "value": value})
            except ValueError as e:
                raise ValueError(f"HINT element ORDINAL attribute must be an integer value: {e}")
        name = element.get("NAME")
        if name:
            self.add(name, {"name": attr_name, "value": value})

if __name__ == "__main__":
    LibraryHints().read_library_hints("/path/to/file.xml")
