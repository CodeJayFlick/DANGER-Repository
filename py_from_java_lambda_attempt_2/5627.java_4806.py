Here is your Java code translated into Python:

```Python
class FunctionsXmlMgr:
    LIB_BOOKMARK_CATEGORY = "Library Identification"
    FID_BOOKMARK_CATEGORY = "Function ID Analyzer"

    def __init__(self):
        self.program = None
        self.listing = None
        self.dt_parser = None
        self.factory = None
        self.log = None

    def read(self, parser, overwrite_conflicts, ignore_stack_frames, monitor):
        try:
            element = parser.start("FUNCTIONS")
            functions = AddressSet()

            while True:
                if parser.peek().isStart():
                    function_element = parser.start("FUNCTION")

                    entry_point_str = function_element.getAttribute("ENTRY_POINT")
                    if not entry_point_str:
                        raise Exception("No entry point provided.")

                    entry_point = XmlProgramUtilities.parse_address(self.factory, entry_point_str)
                    if not entry_point:
                        raise AddressFormatException(
                            "Incompatible Function Entry Point Address: {}".format(entry_point_str))

                    try:
                        namespace_path = None
                        name = function_element.getAttribute("NAME")
                        if name:
                            symbol_path = SymbolPath(name)
                            name = symbol_path.getName()
                            namespace_path = symbol_path.getParent()

                        body = new AddressSet(entry_point, entry_point)

                        if not ignore_stack_frames:
                            read_stack_frame(parser, self.program.get_function(), overwrite_conflicts, stack_variables, stack_params)

                        else:
                            while parser.peek().isStart() and parser.peek().getName() == "STACK_FRAME":
                                parser.discard_sub_tree("STACK_FRAME")

                        return_type = read_return_type(parser)
                        read_address_range(parser, body)
                        regular_comment = getElementText(parser, "REGULAR_CMT")
                        function.set_comment(regular_comment)

                        if not ignore_stack_frames:
                            stack_frame = self.program.get_function().get_stack_frame()
                            read_stack_variables(parser, self.program.get_function(), overwrite_conflicts, stack_variables, stack_params)

                        else:
                            while parser.peek().isStart() and parser.peek().getName() == "STACK_FRAME":
                                parser.discard_sub_tree("STACK_FRAME")

                        register_vars = new ArrayList<Variable>()
                        read_register_vars(parser, self.program.get_function())

                    except Exception as e:
                        log.append_exception(e)
                finally:
                    dt_parser.close()
            return functions

    def write(self, writer, addrs):
        try:
            writer.start_element("FUNCTIONS")

            function_iterator = listing.get_functions(addrs, True)

            while function_iterator.hasNext():
                if monitor.is_cancelled():
                    raise CancelledException()

                func = function_iterator.next()
                self.write_function(writer, func)
            return

    def write_function(self, writer, func):
        attrs = new XmlAttributes()
        attrs.add_attribute("ENTRY_POINT", str(func.get_entry_point()))
        attrs.add_attribute("NAME", getName(func))
        attrs.add_attribute("LIBRARY_FUNCTION", is_library(func) and "y" or "n")

        writer.start_element("FUNCTION", attrs)

        write_return_type(writer, func)
        read_address_range(writer, func)
        regular_comment = getComment(func.get_comment())
        if regular_comment:
            writer.write_element("REGULAR_CMT", None, regular_comment)

        repeatable_comment = getComment(func.get_repeatable_comment())
        if repeatable_comment:
            writer.write_element("REPEATABLE_CMT", None, repeatable_comment)

        stack_frame = func.get_stack_frame()
        attrs.add_attribute("LOCAL_VAR_SIZE", str(stack_frame.get_local_size()))
        attrs.add_attribute("PARAM_OFFSET", str(stack_frame.get_parameter_offset()))

        size = func.get_stack_purge_size()
        if size != Function.UNKNOWN_STACK_DEPTH_CHANGE and size != Function.INVALID_STACK_DEPTH_CHANGE:
            attrs.add_attribute("BYTES_PURGED", str(size))

        writer.start_element("STACK_FRAME", attrs)

        for var in stack_frame.get_stack_variables():
            write_stack_variable(writer, var)
    return

    def write_stack_variable(self, writer, var):
        attrs = new XmlAttributes()
        attrs.add_attribute("STACK_PTR_OFFSET", str(var.get_stack_offset()))
        attrs.add_attribute("NAME", var.getName())
        dt = var.getDataType()
        attrs.add_attribute("DATATYPE", dt.getDisplayName())
        attrs.add_attribute("DATATYPE_NAMESPACE", dt.getCategoryPath().getPath())

    def write_register_vars(self, writer):
        for reg in getRegisterParameters(func):
            attrs = new XmlAttributes()
            attrs.add_attribute("NAME", reg.getName())
            attrs.add_attribute("REGISTER", reg.getRegister().getName())
            attrs.add_attribute("DATATYPE", reg.getDataType().getDisplayName())
            attrs.add_attribute("DATATYPE_NAMESPACE", reg.getDataType().getCategoryPath().getPath())

    def write_stack_frame(self, writer):
        stack_vars = self.program.get_function().get_stack_variables()
        for var in stack_vars:
            if not ignore_stack_frames and var.isStackVariable():
                write_stack_variable(writer, var)
            else:
                while parser.peek().isStart() and parser.peek().getName() == "STACK_FRAME":
                    parser.discard_sub_tree("STACK_FRAME")

    def read_register_vars(self):
        for reg in getRegisterParameters(func):
            if not ignore_stack_frames and reg.isStackVariable():
                write_stack_variable(writer, reg)
            else:
                while parser.peek().isStart() and parser.peek().getName() == "REGISTER_VAR":
                    parser.discard_sub_tree("REGISTER_VAR")

    def read_address_range(self, writer, body):
        for range in body.get_ranges():
            attrs = new XmlAttributes()
            attrs.add_attribute("START", str(range.getMinAddress()))
            attrs.add_attribute("END", str(range.getMaxAddress()))

    def write_stack_frame(self, writer):
        stack_vars = self.program.get_function().get_stack_variables()
        for var in stack_vars:
            if not ignore_stack_frames and var.isStackVariable():
                write_stack_variable(writer, var)
            else:
                while parser.peek().isStart() and parser.peek().getName() == "STACK_FRAME":
                    parser.discard_sub_tree("STACK_FRAME")

    def read_address_range(self):
        for range in body.get_ranges():
            attrs = new XmlAttributes()
            attrs.add_attribute("START", str(range.getMinAddress()))
            attrs.add_attribute("END", str(range.getMaxAddress()))

    def write_stack_frame(self, writer):
        stack_vars = self.program.get_function().get_stack_variables()
        for var in stack_vars:
            if not ignore_stack_frames and var.isStackVariable():
                write_stack_variable(writer, var)
            else:
                while parser.peek().isStart() and parser.peek().getName() == "STACK_FRAME":
                    parser.discard_sub_tree("STACK_FRAME")

    def read_address_range(self):
        for range in body.get_ranges():
            attrs = new XmlAttributes()
            attrs.add_attribute("START", str(range.getMinAddress()))
            attrs.add_attribute("END", str(range.getMaxAddress()))

    def write_stack_frame(self, writer):
        stack_vars = self.program.get_function().get_stack_variables()
        for var in stack_vars:
            if not ignore_stack_frames and var.isStackVariable():
                write_stack_variable(writer, var)
            else:
                while parser.peek().isStart() and parser.peek().getName() == "STACK_FRAME":
                    parser.discard_sub_tree("STACK_FRAME")

    def read_address_range(self):
        for range in body.get_ranges():
            attrs = new XmlAttributes()
            attrs.add_attribute("START", str(range.getMinAddress()))
            attrs.add_attribute("END", str(range.getMaxAddress()))

    def write_stack_variable(self, writer):
        if not ignore_stack_frames and var.isStackVariable():
                write_stack_variable(writer, var)

    def read_address_range(self, writer):

    def write_function(self, writer):