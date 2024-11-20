Here is the translation of the Java code into Python:

```Python
import xml.etree.ElementTree as ET
from typing import List

class FileBitPatternInfo:
    def __init__(self):
        self.num_first_bytes = 0
        self.num_first_instructions = 0
        self.num_pre_bytes = 0
        self.num_pre_instructions = 0
        self.num_return_bytes = 0
        self.num_return_instructions = 0
        self.language_id = None
        self.ghidra_url = None
        self.func_bit_pattern_info: List['FunctionBitPatternInfo'] = []

    def to_xml(self):
        root = ET.Element('FileBitPatternInfo')
        if self.ghidra_url:
            root.set('ghidraURL', self.ghidra_url)
        if self.language_id:
            root.set('languageID', self.language_id)
        root.set('numFirstBytes', str(self.num_first_bytes))
        root.set('numFirstInstructions', str(self.num_first_instructions))
        root.set('numPreBytes', str(self.num_pre_bytes))
        root.set('numPreInstructions', str(self.num_pre_instructions))
        root.set('numReturnBytes', str(self.num_return_bytes))
        root.set('numReturnInstructions', str(self.num_return_instructions))

        func_bit_pattern_info_list = ET.SubElement(root, 'funcBitPatternInfoList')
        for fbpi in self.func_bit_pattern_info:
            func_bit_pattern_info_list.append(fbpi.to_xml())

        return ET.ElementTree(root)

    @classmethod
    def from_xml(cls, element):
        ghidra_url = element.get('ghidraURL') if element.get('ghidraURL') else None
        language_id = element.get('languageID') if element.get('languageID') else None

        num_first_bytes = int(element.get('numFirstBytes'))
        num_first_instructions = int(element.get('numFirstInstructions'))
        num_pre_bytes = int(element.get('numPreBytes'))
        num_pre_instructions = int(element.get('numPreInstructions'))
        num_return_bytes = int(element.get('numReturnBytes'))
        num_return_instructions = int(element.get('numReturnInstructions'))

        func_bit_pattern_info_list: List['FunctionBitPatternInfo'] = []
        for child_element in element.findall('.//functionbitpatterninfo'):
            func_bit_pattern_info_list.append(FunctionBitPatternInfo.from_xml(child_element))

        result = cls()
        result.func_bit_pattern_info = func_bit_pattern_info_list
        result.ghidra_url = ghidra_url
        result.language_id = language_id
        result.num_first_bytes = num_first_bytes
        result.num_first_instructions = num_first_instructions
        result.num_pre_bytes = num_pre_bytes
        result.num_pre_instructions = num_pre_instructions
        result.num_return_bytes = num_return_bytes
        result.num_return_instructions = num_return_instructions

        return result


class FunctionBitPatternInfo:
    XML_ELEMENT_NAME = 'functionbitpatterninfo'

    def __init__(self):
        self.func_bit_pattern_info: List[ET.Element] = []

    @classmethod
    def from_xml(cls, element):
        func_bit_pattern_info_list: List['FunctionBitPatternInfo'] = []
        for child_element in element.findall('.//' + cls.XML_ELEMENT_NAME):
            func_bit_pattern_info_list.append(FunctionBitPatternInfo.from_xml(child_element))

        result = cls()
        result.func_bit_pattern_info = func_bit_pattern_info_list

        return result


def to_xml_file(file_path, file_bit_pattern_info: FileBitPatternInfo) -> None:
    root = file_bit_pattern_info.to_xml().getroot()

    ET.ElementTree(root).write(file_path)


def from_xml_file(file_path) -> FileBitPatternInfo:
    try:
        tree = ET.parse(file_path)
        return FileBitPatternInfo.from_xml(tree.getroot())
    except ET.ParseError as e:
        print(f"Failed to read file bit pattern {file_path}: {e}")
        raise
```

Please note that this translation is not a direct conversion, but rather an equivalent Python code. The Java code has been rewritten in Python using the `xml.etree.ElementTree` module for XML manipulation and list comprehensions where applicable.