import xml.etree.ElementTree as ET
from typing import List

class ImportFromXMLAction:
    def __init__(self, tool: str, owner: str, provider: object):
        self.file_ext = ".xml"
        self.file_mode = "FILES_ONLY"

    def is_enabled_for_context(self, context: dict) -> bool:
        return True

    def do_action(self, container: object, file_path: str) -> None:
        import threading
        from xml.etree.ElementTree import Element

        try:
            root = ET.parse(file_path).getroot()
            path_str = root.attrib.get("Path")
            if path_str is not None:
                path = [s for s in path_str.split(".") if s]
            else:
                path = []

            to = self.xml_to_object(provider, root, path)
            provider.update(to)

        except Exception as e:
            print(f"Load Failed: {e}")

    def xml_to_object(self, provider: object, element: Element, path: List[str]) -> object:
        key = convert_name(element.tag)
        type_attr = element.attrib.get("Type")
        value_attr = element.attrib.get("Value")

        objects = []
        for child in list(element):
            if isinstance(child, ET.Element):
                npath = [s for s in path]
                npath.append(convert_name(child.tag))
                to = self.xml_to_object(provider, child, npath)
                objects.append(to)

        tstr = type_attr if type_attr is not None else ""
        vstr = value_attr if value_attr is not None else ""

        return DummyTargetObject(key, path, tstr, vstr, "", objects)


def convert_name(name: str) -> str:
    if "_0x" in name:
        return "[" + name.split("_")[1] + "]"
    return name


class DummyTargetObject:
    def __init__(self, key: str, path: List[str], tstr: str, vstr: str, desc: str, objects: List[object]):
        self.key = key
        self.path = path
        self.tstr = tstr
        self.vstr = vstr
        self.desc = desc
        self.objects = objects


# Example usage:
provider = object()  # Replace with your actual provider
action = ImportFromXMLAction("tool", "owner", provider)
container = object()  # Replace with your actual container
file_path = "/path/to/file.xml"
action.do_action(container, file_path)
