import xml.etree.ElementTree as ET
from typing import Iterator

class EquatesXmlMgr:
    def __init__(self, program: dict, log: list):
        self.log = log
        self.equate_table = program['equate_table']

    def read(self, parser: ET._ElementIterator, monitor) -> None:
        while True:
            if monitor.is_cancelled():
                raise CancelledException()
            element = next(parser)
            if not isinstance(element.tag, str) or element.tag != "EQUATE_GROUP":
                break
            self.process_equate_group(parser, monitor)

    def write(self, writer: ET._ElementTree, set: dict, monitor) -> None:
        monitor.set_message("Writing EQUATES ...")
        root = ET.Element('EQUATES')
        equate_group = ET.SubElement(root, 'EQUATE_GROUP')

        for equate in self.equate_table['equates']:
            if monitor.is_cancelled():
                raise CancelledException()
            attrs = {'NAME': equate.name}
            value_str = str(equate.value)
            attr_value = f'{{value}}'
            writer.SubElement(equate_group, 'EQUATE', attrs).text = value_str
        root.append(equate_group)

    def process_equate_group(self, parser: ET._ElementIterator, monitor) -> None:
        while True:
            if monitor.is_cancelled():
                raise CancelledException()
            element = next(parser)
            if not isinstance(element.tag, str):
                break

            if element.tag in ['DISPLAY_SETTINGS', 'REGULAR_CMT', 'REPEATABLE_CMT', 'BIT_MASK']:
                parser.next()

    def process_equate(self, parser: ET._ElementIterator) -> None:
        if not isinstance(parser.peek().tag, str) or parser.peek().tag != "EQUATE":
            return

        name = parser.peek().attrib['NAME']
        value = int(parser.peek().attrib['VALUE'], 16)

        try:
            self.equate_table.create_equate(name, value)
        except DuplicateNameException as e:
            prev_value = self.equate_table.get_equate(name).value
            if prev_value != value:
                self.log.append(f"Cannot create equate {name} with value {hex(value)}; previously defined with value {hex(prev_value)}")
        except Exception as e:
            self.log.append(str(e))

    def write_equate(self, writer: ET._ElementTree, equate: dict) -> None:
        if not isinstance(writer.root.tag, str):
            return

        attrs = {'NAME': equate['name']}
        value_str = f'{{value}}'
        writer.SubElement(writer.root, 'EQUATE', attrs).text = value_str
