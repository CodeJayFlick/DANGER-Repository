import xml.etree.ElementTree as ET
from io import StringIO
from threading import Thread


class XmlPullParserFactory:
    def set_create_tracing_parsers(self):
        raise NotImplementedError("XmlTracer not supported right now...instrument ThreadedXmlPullParserImpl to continue...")

    @staticmethod
    def create(input, input_name, err_handler=None, validate=False):
        if isinstance(input, str):
            return ET.fromstring(input)
        elif isinstance(input, bytes):
            tree = ET.parse(StringIO(input.decode('utf-8')))
            return tree.getroot()
        else:
            raise ValueError("Invalid input type")

    @staticmethod
    def create_file(file_path, err_handler=None, validate=False):
        try:
            with open(file_path, 'r') as file:
                return ET.fromstring(file.read())
        except Exception as e:
            print(f"Error reading file: {e}")
            raise

# Example usage:

factory = XmlPullParserFactory()
xml_string = "<root><child>hello</child></root>"
parsing_result = factory.create(xml_string, "XML String", validate=True)
print(parsing_result)

file_path = 'path_to_your_xml_file.xml'
parsed_tree = factory.create_file(file_path, validate=False)
print(parsed_tree)
