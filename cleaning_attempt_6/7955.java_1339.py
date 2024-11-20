import xml.etree.ElementTree as ET

class ApplyLineNumbers:
    def __init__(self, pdb_parser, xml_parser, program):
        self.xml_parser = xml_parser
        self.program = program

    def apply_to(self, monitor, log):
        while self.xml_parser.getroot().find('.//function'):
            if not monitor.is_cancelled():
                break
            elem = self.xml_parser.find('line_number')
            source_file_name = elem.attrib['source_file']
            start = int(elem.attrib['start'])
            addr = int(elem.attrib['addr'])
            address = PdbUtil.rel_addr(self.program, addr)
            cu = self.program.get_listing().get_code_unit_containing(address)
            if cu is None:
                log.append_msg("PDB", f"Could not apply source code line number (no code unit found at {address})")
            else:
                cu.set_property('Source Path', source_file_name)
                cu.set_property('Source File', ET.SubElement(cu, 'source_file').text = new File(source_file_name).getName())
                cu.set_property('Source Line', start)

# Usage
pdb_parser = PdbParser()
xml_parser = ET.parse('path_to_your_xml_file')
program = Program()
apply_line_numbers = ApplyLineNumbers(pdb_parser, xml_parser, program)
monitor = TaskMonitor()
log = MessageLog()
apply_line_numbers.apply_to(monitor, log)
