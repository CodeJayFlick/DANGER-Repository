Here is the translation of the given Java code into equivalent Python:

```Python
import xml.etree.ElementTree as ET

class ApplySymbols:
    def __init__(self):
        pass  # static use only

    @staticmethod
    def apply_to(pdb_parser, xmlPullParser, task_monitor, message_log):
        program = pdb_parser.get_program()
        function_manager = program.get_function_manager()
        tag_set = set()  # equivalent to HashSet in Java
        disassemble_set = set()

        while xmlPullParser.has_next():
            if task_monitor.is_cancelled():
                return

            elem = ET.Element(xmlPullParser.next())
            if elem.tag == "table" and not xmlPullParser.has_next():  # skip end element
                break

            name = elem.get("name")
            addr = int(elem.get("address"))
            length = int(elem.get("length"))
            tag = elem.get("tag")

            datatype = SymbolUtilities.replace_invalid_chars(elem.get("datatype"), False)

            if not name or addr == 0:
                continue

            # We do not need additional symbols for Functions;
            # we already have what we need from the Functions section.
            if "Function".equals(tag):
                continue

            address = PdbUtil.reladdr(program, addr)
            task_monitor.set_message("Applying symbol at {}...".format(address))

            force_primary = should_force_primary_symbol(program, address)

            if "Block".equals(tag):  # Only create pre-comment from Block symbol
                pre_comment = "PDB: Start of Block"
                if not name.endswith("$"):
                    pre_comment += " ({})".format(name)
                PdbUtil.append_comment(program, address, pre_comment, CodeUnit.PRE_COMMENT)

            elif length == 0:
                # avoid creating symbol which may correspond to inline function code
                PdbUtil.append_comment(program, address, "Symbol Ref: @symbol {}".format(name), CodeUnit.PRE_COMMENT)
                continue

            if not "Data".equals(tag):
                pdb_parser.create_symbol(address, name, force_primary, message_log)

        memory_blocks = program.get_memory().get_blocks()
        for block in memory_blocks:
            if not block.is_execute():
                disassemble_set.discard(range(block.start(), block.end()))

        task_monitor.set_message("Disassembling...")
        cmd = DisassembleCommand(disassemble_set, None, True)
        cmd.apply_to(program, task_monitor)

    @staticmethod
    def should_force_primary_symbol(program, address):
        primary_symbol = program.get_symbol_table().get_primary_symbol(address)
        if primary_symbol:
            return True

        return False


# Python does not have direct equivalent of Java's HashSet and XmlPullParser.
```

Note: The above code is a translation from the given Java code into equivalent Python. It may require some modifications to work correctly in your specific use case, as it was written based on my understanding of the provided Java code.