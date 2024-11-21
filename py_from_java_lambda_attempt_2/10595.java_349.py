Here is the translation of the Java code into Python:

```Python
import xml.etree.ElementTree as ET
from collections import defaultdict

class XmlUtilities:
    LESS_THAN = "&lt;"
    GREATER_THAN = "&gt;"
    APOSTROPHE = "&apos;"
    QUOTE = "&quot;"
    AMPERSAND = "&amp;"

    HEX_DIGIT_PATTERN = r"[&][#][x]([\\da-afA-F]+)[;]"

    FEATURE_DISALLOW_DTD = "http://apache.org/xml/features/disallow-doctype-decl"
    FEATURE_EXTERNAL_GENERAL_ENTITIES = "http://xml.org/sax/features/external-general-entities"
    FEATURE_EXTERNAL_PARAMETER_ENTITIES = "http://xml.org/sax/features/external-parameter-entities"

    def __init__(self):
        pass

    @staticmethod
    def throwing_error_handler(exception):
        raise SAXException(exception)

    @staticmethod
    def escape_element_entities(xml_string):
        buffer = StringBuffer()
        for i in range(len(xml_string)):
            next_char = xml_string[i]
            if (next_char < ' ') and (next_char != 0x09) and (next_char != 0x0A) and (next_char != 0x0D):
                continue
            elif next_char >= 0x7F:
                buffer.append("&#x")
                buffer.append(hex(next_char)[2:].upper())
                buffer.append(";")
                continue
            match = re.match(XmlUtilities.HEX_DIGIT_PATTERN, xml_string[i:])
            if match:
                buffer.append(match.group(1))
                break
        return buffer.toString()

    @staticmethod
    def unescape_element_entities(escaped_xml_string):
        matcher = re.compile(XmlUtilities.HEX_DIGIT_PATTERN)
        buffy = StringBuffer()
        while True:
            match = matcher.search(escaped_xml_string)
            if not match:
                break
            int_value = int(match.group(1), 16)
            buffy.append(chr(int_value))
            escaped_xml_string = escaped_xml_string[match.end():]
        return buffy.toString()

    @staticmethod
    def xml_to_byte_array(root):
        os = ByteArrayOutputStream()
        doc = ET.fromstring(str(root).encode("utf-8"))
        outputter = XMLOutputter()
        try:
            outputter.output(doc, os)
            os.close()
            return os.toByteArray()
        except Exception as e:
            print(f"Unexpected exception: {e}")

    @staticmethod
    def parse_overlay_name(addr_str):
        index = addr_str.find("::")
        if index > 0:
            return addr_str[:index]
        else:
            return None

    @staticmethod
    def parse_int(int_str, min_value=0, max_value=int.MAX_VALUE):
        try:
            value = int(int_str)
            if not (min_value <= value <= max_value):
                raise ValueError(f"Integer value {value} out of range: [{min_value}..{max_value}]")
            return value
        except Exception as e:
            print(f"Error parsing integer: {e}")

    @staticmethod
    def parse_long(long_str, min_value=0, max_value=int.MAX_VALUE):
        try:
            value = int(long_str)
            if not (min_value <= value <= max_value):
                raise ValueError(f"Long value {value} out of range: [{min_value}..{max_value}]")
            return value
        except Exception as e:
            print(f"Error parsing long integer: {e}")

    @staticmethod
    def parse_boolean(bool_str, default=False):
        if bool_str is None or len(bool_str) == 0:
            return default
        elif bool_str.lower() in ["y", "true"]:
            return True
        else:
            return False

    @staticmethod
    def require_string_attr(ele, attr_name):
        value = ele.find(attr_name).text if ele.find(attr_name) is not None else ""
        if len(value) == 0 or value.isspace():
            raise ValueError(f"Missing required attribute: {attr_name}")
        return value

    @staticmethod
    def set_string_attr(ele, attr_name, attr_value):
        if attr_value:
            ele.set(attr_name, attr_value)

    @staticmethod
    def get_children(ele, child_name):
        children = []
        for child in ele.findall(child_name):
            children.append(ET.tostring(child))
        return children

class SAXException(Exception): pass