class MarkupXmlMgr:
    def __init__(self, program, log):
        self.program = program
        self.log = log

    # XML READ CURRENT DTD
    def read(self, parser, overwrite, ignore_stack_references=False, monitor=None):
        try:
            while True:
                element = parser.next()
                if not element.isStart() or element.getName().upper() != "MARKUP":
                    raise SAXParseException("Expected MARKUP start tag", None, None,
                                             parser.getLineNumber(), parser.getColumnNumber())
                break
            while True:
                if monitor is not None and monitor.isCancelled():
                    raise CancelledException()
                tagName = element.getName().upper()
                if tagName == "MEMORY_REFERENCE":
                    self.process_memory_reference(element, overwrite)
                elif tagName == "STACK_REFERENCE":
                    self.process_stack_reference(element, overwrite)
                elif tagName == "EXT_LIBRARY_REFERENCE":
                    self.process_ext_library_reference(element, overwrite)
                elif tagName == "EQUATE_REFERENCE":
                    self.process_equate_reference(element, overwrite)
        except Exception as e:
            log.appendException(e)

    # XML WRITE CURRENT DTD
    def write(self, writer, set, monitor=None):
        if set is None:
            set = self.program.getMemory()
        try:
            while True:
                element = parser.next()
                if not element.isStart() or element.getName().upper() != "MARKUP":
                    raise SAXParseException("Expected MARKUP start tag", None, None,
                                             parser.getLineNumber(), parser.getColumnNumber())
                break
            writer.startElement("MARKUP")
            monitor.setMessage("Exporting References...")
            for ref in self.program.getReferenceManager().getReferenceSourceIterator(set):
                if isinstance(ref, MemoryReference) and ref.getSource() == SourceType.USER_DEFINED:
                    self.write_memory_reference(writer, ref)
                elif isinstance(ref, StackReference) and ref.getSource() == SourceType.USER_DEFINED:
                    self.write_stack_reference(writer, ref)
                elif isinstance(ref, ExternalReference) and ref.getSource() == SourceType.USER_DEFINED:
                    self.write_external_reference(writer, ref)
            writer.endElement("MARKUP")
        except CancelledException as e:
            raise

    # WRITE MEMORY REFERENCE
    def write_memory_reference(self, writer, ref):
        if ref.getFromAddress().isOffsetReference():
            attr = {"ADDRESS": str(ref.getToAddress()), "BASE_ADDRESS": str(((OffsetReference)ref).getBaseAddress())}
        elif ref.getFromAddress().isShiftedReference():
            # TODO: Handle ShiftedReference
            pass
        else:
            attr = {"ADDRESS": str(ref.getToAddress()), "PRIMARY": ref.isPrimary()}
        writer.writeElement("MEMORY_REFERENCE", attr)

    # WRITE STACK REFERENCE
    def write_stack_reference(self, writer, ref):
        if isinstance(ref, StackReference) and ref.getSource() == SourceType.USER_DEFINED:
            attr = {"ADDRESS": str(ref.getFromAddress()), "STACK_PTR_OFFSET": str(ref.getStackOffset())}
            writer.writeElement("STACK_REFERENCE", attr)

    # WRITE EXTERNAL REFERENCE
    def write_external_reference(self, writer, ref):
        if isinstance(ref, ExternalReference) and ref.getSource() == SourceType.USER_DEFINED:
            ext_loc = ref.getExternalLocation()
            attr = {"LIB_PROG_NAME": str(ext_loc.getLibraryName()), "LIB_LABEL": str(ext_loc.getLabel()),
                    "LIB_ADDR": str(ext_loc.getAddress())}
            writer.writeElement("EXT_LIBRARY_REFERENCE", attr)

    # WRITE EQUATE REFERENCES
    def write_equate_references(self, writer, set):
        for equate in self.program.getEquateTable().getEquates():
            name = equate.getName()
            value = equate.getValue()
            refs = equate.getReferences()
            for ref in refs:
                if not set.contains(ref.getAddress()):
                    continue
                attr = {"ADDRESS": str(ref.getAddress()), "OPERAND_INDEX": ref.getOpIndex(), "NAME": name, "VALUE": value}
                writer.writeElement("EQUATE_REFERENCE", attr)
