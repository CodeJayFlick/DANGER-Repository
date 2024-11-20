Here is the translation of the Java code to Python:
```
import xml.etree.ElementTree as ET

class SpacebaseSpace:
    def __init__(self, name: str, index: int, size: int, base_space: 'AddrSpace', depth_level: int):
        super().__init__(base_space.get_trans(), "IPTR_SPACEBASE", name, size, base_space.get_word_size(), index, 0, depth_level)
        self.contain = base_space

    def get_contain(self) -> 'AddrSpace':
        return self.contain

    @classmethod
    def from_translate(cls, t: object):
        instance = cls(t)
        return instance

    def save_xml(self, stream: object):
        stream.write("<space_base")
        self.save_basic_attributes(stream)
        XmlUtils.a_v(stream, "contain", self.contain.name)
        stream.write("/>\n")

    @classmethod
    def restore_xml(cls, element: ET.Element):
        super().restore_xml(element)  # Restore basic attributes
        contain_name = element.get("contain")
        self.contain = cls.from_translate(get_trans()).get_space_by_name(contain_name)

class XmlUtils:
    @staticmethod
    def a_v(stream: object, attr_name: str, value: str):
        stream.write(f"<{attr_name}>{value}</{attr_name}>")

# Note: The following classes are not translated as they were not provided in the original code.
class AddrSpace:
    pass

class Translate:
    pass
```
Note that I had to make some assumptions about the `AddrSpace` and `Translate` classes, since their implementation was not provided. You may need to modify this translation accordingly.

Also, I used Python's built-in `xml.etree.ElementTree` module for XML-related operations, as it is more convenient than implementing your own XML parsing logic.