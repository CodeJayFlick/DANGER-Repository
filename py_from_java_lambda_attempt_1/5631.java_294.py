Here is the translation of the Java code into Python:

```Python
class ProgramTreeXmlMgr:
    def __init__(self, program, log):
        self.log = log
        self.listing = program.get_listing()
        self.factory = program.get_address_factory()

    def read(self, parser, monitor, add_to_program=False) -> None:
        if not add_to_program:
            self.listing.remove_tree(PluginConstants.DEFAULT_TREE_NAME)

        trees = parser.start("PROGRAM_TREES")
        while True:
            try:
                element = parser.next()
                self.process_tree(element, parser)
            except Exception as e:
                log.append_exception(e)
                parser.discard_subtree(element)
            if monitor.is_cancelled():
                raise CancelledException()

    def write(self, writer, addrs, monitor) -> None:
        monitor.set_message("Writing PROGRAM TREES...")
        writer.start_element("PROGRAM_TREES")
        tree_names = self.listing.get_tree_names()
        for i in range(len(tree_names)):
            if monitor.is_cancelled():
                raise CancelledException()

            attrs = XmlAttributes()
            attrs.add_attribute("NAME", tree_names[i])
            writer.start_element("TREE", attrs)

            root_module = self.listing.get_root_module(tree_names[i])

            written_modules = []
            written_fragments = []

            self.write_module(writer, addrs, root_module, written_modules, written_fragments)
            writer.end_element("TREE")
        writer.end_element("PROGRAM_TREES")

    def process_tree(self, tree_element: XmlElement, parser) -> None:
        if not monitor.is_cancelled():
            try:
                name = tree_element.get_attribute("NAME")
                fragment_name_list = []

                root_module = self.listing.create_root_module(name)
                module_stack = [root_module]

                element = parser.next()
                while True:
                    if not monitor.is_cancelled():
                        try:
                            if element.name == "FRAGMENT" or element.name == "MODULE" or element.name == "FOLDER":
                                if element.name == "FRAGMENT":
                                    self.process_fragment(element, parser)
                                else:
                                    module_stack.pop()
                            elif element.name != "PROGRAM_TREES":
                                break
                        except Exception as e:
                            log.append_exception(e)
                            parser.discard_subtree(tree_element)

                remove_empty_fragments(root_module)
            except CancelledException:
                pass

    def process_fragment(self, element: XmlElement, parser) -> None:
        if not monitor.is_cancelled():
            try:
                name = element.get_attribute("NAME")
                parent = module_stack[-1]
                fragment = self.listing.create_fragment(name)

                if not fragment_name_list.contains(name):
                    fragment_name_list.add(name)
                    parent.add(fragment)

                process_fragment_range(fragment, parser)
            except Exception as e:
                log.append_exception(e)
                parser.discard_subtree(element)

    def remove_empty_fragments(self, module: ProgramModule) -> None:
        groups = module.get_children()
        for i in range(len(groups)):
            if isinstance(groups[i], ProgramFragment):
                name = groups[i].get_name()
                if not fragment_name_list.contains(name):
                    try:
                        module.remove_child(name)
                    except NotEmptyException as e:
                        log.append_msg("Warning: Extra Program Tree fragment '" + name +
                                       "' did not exist in imported XML file")
            else:
                self.remove_empty_fragments(groups[i])

    def write_module(self, writer, addrs, parent: ProgramModule, written_modules, written_fragments) -> None:
        if not written_modules.contains(parent):
            written_modules.add(parent)
            groups = parent.get_children()
            for i in range(len(groups)):
                if isinstance(groups[i], ProgramModule):
                    self.write_module(writer, addrs, groups[i], written_modules, written_fragments)
                else:
                    self.write_fragment(writer, addrs, groups[i], written_fragments)

    def write_fragment(self, writer, addrs, fragment: ProgramFragment, written_fragments) -> None:
        if not monitor.is_cancelled():
            try:
                address_set_view = addrs.intersect(fragment)
                if address_set_view.empty():
                    return
                attrs = XmlAttributes()
                attrs.add_attribute("NAME", fragment.get_name())
                writer.start_element("FRAGMENT", attrs)

                if not written_fragments.contains(fragment):
                    written_fragments.add(fragment)
                    self.write_fragment_range(writer, fragment, address_set_view)
                writer.end_element("FRAGMENT")
            except Exception as e:
                log.append_exception(e)

    def write_fragment_range(self, writer, fragment: ProgramFragment, addrs) -> None:
        iter = addrs.get_address_ranges()
        while True:
            try:
                attrs = XmlAttributes()
                range = iter.next()
                attrs.add_attribute("START", str(range.min_address))
                attrs.add_attribute("END", str(range.max_address))
                writer.start_element("ADDRESS_RANGE", attrs)
                writer.end_element("ADDRESS_RANGE")
            except Exception as e:
                log.append_exception(e)

    def process_fragment_range(self, fragment: ProgramFragment, parser) -> None:
        if not monitor.is_cancelled():
            try:
                element = parser.next()
                while True:
                    if not monitor.is_cancelled():
                        try:
                            if element.name == "ADDRESS_RANGE":
                                start_str = element.get_attribute("START")
                                end_str = element.get_attribute("END")

                                start_address = XmlProgramUtilities.parse_address(self.factory, start_str)
                                end_address = XmlProgramUtilities.parse_address(self.factory, end_str)

                                if start_address is None or end_address is None:
                                    raise AddressFormatException(
                                        "Incompatible Fragment Address Range: [" + start_str +
                                        "," + end_str + "]")
                                fragment.move(start_address, end_address)
                            else:
                                break
                        except Exception as e:
                            log.append_exception(e)
                            parser.discard_subtree(element)

            except NotFoundException as e:
                log.append_msg(e.get_message())
                parser.discard_subtree(element)
```

Note that this is a direct translation of the Java code into Python, and may not be perfect. The `XmlAttributes`, `XmlElement`, `AddressSetView` classes are not part of standard Python libraries, so you would need to implement them yourself or use an existing library like `xml.etree.ElementTree`.