import xml.etree.ElementTree as ET
from unittest import TestCase


class XmlUtilitiesTest(TestCase):

    def test_xml_to_bytes(self):
        root = ET.Element("ROOT")
        row_elem = ET.SubElement(root, "ROW")

        col_elem = ET.SubElement(row_elem, "COL")
        col_elem.set('WIDTH', '200')
        col_elem.set('ENABLED', 'true')

        field_elem = ET.SubElement(row_elem, "FIELD")
        field_elem.set('NAME', 'AAA')
        field_elem.set('WIDTH', '100')
        field_elem.set('ENABLED', 'true')

        bytes = XmlUtilities.xml_to_bytes(root)
        e = XmlUtilities.bytes_to_xml(bytes)

        self.assertEqual("ROOT", e.tag)
        children = list(e)
        self.assertEqual(1, len(children))
        c1 = children[0]
        self.assertEqual("ROW", c1.tag)
        children = list(c1)
        self.assertEqual(2, len(children))
        c1 = children[0]
        self.assertEqual("COL", c1.tag)
        c2 = children[1]
        self.assertEqual("FIELD", c2.tag)

    def test_has_invalid_xml_chars(self):
        self.assertTrue(XmlUtilities.has_invalid_xml_characters('\x00'))

        for ch in range(256):  # Check all ASCII characters
            if not XmlUtilities.has_invalid_xml_characters(chr(ch)):
                self.test_char_as_attr_value(ch)
            else:
                break

    @staticmethod
    def test_char_as_attr_value(ch):
        node = ET.Element("node")
        node.set('attr', str(ch))
