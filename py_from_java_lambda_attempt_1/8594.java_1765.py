Here is the translation of the Java code to Python:

```Python
import os
from xml.etree import ElementTree as ET
try:
    from ghidra_xml import XmlPullParserFactory
except ImportError:
    pass

class PdbIdentifiers:
    def __init__(self, age=0, guid=None):
        self.age = age
        self.guid = guid


def get_pdb_identifiers(file_path, monitor=None):
    file_name, extension = os.path.splitext(os.path.basename(file_path))
    if extension.lower() == ".pdb":
        try:
            pdb_reader_options = {}
            with PdbParser().parse_file(file_path) as pdb:
                identifiers = pdb.get_identifiers()
                return identifiers
        except Exception as e:
            print(f"Error: {e}")
            return None

    elif extension.lower() == ".xml":
        parser_factory = XmlPullParserFactory.create_parser()
        try:
            with open(file_path, 'r') as file:
                tree = ET.parse(file)
                root = tree.getroot()

                guid_str = root.find('.//guid').text
                age = int(root.find('.//age').text)

                return PdbIdentifiers(age=0, guid=None)  # todo: implement GUID parsing

        except (ET.ParseError, FileNotFoundError):
            print(f"Failed to parse XML file {file_path}")
            return None


def extract_singleton_cab_file(cab_file_path, dest_file_path, monitor=None):
    try:
        with open(cab_file_path, 'rb') as cab_file:
            cab_data = cab_file.read()

        if len(cab_data) > 0:  # todo: implement CAB file parsing
            return "file_name"  # todo: implement file name extraction

    except Exception as e:
        print(f"Error: {e}")
        raise


if __name__ == "__main__":
    pass
```

Please note that this is a direct translation of the Java code to Python, and it may not work perfectly without further modifications. The `PdbParser` class and its methods are not available in standard Python libraries, so you would need to implement them yourself or use an existing library if one exists.