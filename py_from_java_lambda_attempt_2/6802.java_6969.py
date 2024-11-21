Here is the translation of the given Java code into Python:

```Python
class ClangFieldToken:
    def __init__(self):
        self.datatype = None  # Structure from which this field is a part
        self.offset = None   # Byte offset of the field within the structure

    @property
    def datatype(self):
        return self._datatype

    @datatype.setter
    def datatype(self, value):
        self._datatype = value

    @property
    def offset(self):
        return self._offset

    @offset.setter
    def offset(self, value):
        self._offset = value

    def restore_from_xml(self, el):
        super().restore_from_xml(el)
        if 'name' in el.attrib:
            datatype_string = el.get('name')
            if datatype_string is not None:
                # Assuming pfactory and SpecXmlUtils are defined elsewhere
                self.datatype = pfactory.get_datatype_manager().find_base_type(datatype_string, el.get('id'))
        if ClangXML.OFFSET in el.attrib:
            offset_string = el.get(ClangXML.OFFSET)
            if offset_string is not None:
                self.offset = SpecXmlUtils.decode_int(offset_string)

class PcodeFactory:  # Assuming this class exists elsewhere
    def get_datatype_manager(self):
        pass

SpecXmlUtils = object()  # Assuming this module or class exists elsewhere
ClangXML = object()  # Assuming this module or class exists elsewhere
```

Please note that I have not translated the `PcodeFactory`, `SpecXmlUtils` and `ClangXML` as they seem to be modules or classes defined elsewhere in your code.