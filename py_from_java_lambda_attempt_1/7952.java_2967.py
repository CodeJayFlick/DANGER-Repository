Here is the translation of the Java code to Python:

```Python
class ApplyDataTypes:
    def __init__(self, pdb_parser: 'PdbParser', log: 'MessageLog'):
        self.pdb_parser = pdb_parser
        self.log = log

    def dispose(self):
        self.composite_queue.clear()

    @staticmethod
    def get_composite_definitions_in_post_dependency_order(composite_queue: dict, monitor) -> list:
        graph = GDirectedGraph()
        for composite_definition in composite_queue.values():
            graph.add_vertex(composite_definition)
            for member in composite_definition.member_list:
                name = member.member_data_type_name
                index = name.find('[')
                if index > 0:
                    name = name[:index].strip()
                child = composite_queue.get(name)
                if child is not None:
                    graph.add_edge(DefaultGEdge(composite_definition, child))
        return GraphAlgorithms.get_vertices_in_post_order(graph)

    def build_data_types(self, monitor):
        monitor.set_message("Order PDB datatypes...")
        vertices_in_post_order = self.get_composite_definitions_in_post_dependency_order(self.composite_queue, monitor)
        monitor.set_message("Building PDB datatypes...")
        for composite_definition in vertices_in_post_order:
            if not DefaultCompositeMember.apply_data_type_members(composite_definition):
                continue
            # rest of the code...

    def pre_process_data_type_list(self, xml_parser: 'XmlPullParser', is_classes: bool, monitor) -> None:
        while xml_parser.has_next():
            monitor.check_cancelled()
            elem = xml_parser.peek()
            if elem.is_end() and elem.get_name().lower() == "datatypes":
                break
            composite_definition = CompositeDefinition(xml_parser)
            self.composite_queue[composite_definition.name] = composite_definition

    def get_normal_members_only(self, composite_definition: 'CompositeDefinition') -> list:
        return [member for member in composite_definition.member_list if member.kind == PdbKind.MEMBER]

class CompositeDefinition:
    def __init__(self, xml_parser):
        self.is_class = False
        self.kind = None
        self.name = ""
        self.length = 0
        self.has_normal_members_only = True
        self.member_list = []
        start_element = xml_parser.start()
        self.name = SymbolUtilities.replace_invalid_chars(start_element.get_attribute("name"), False)
        self.length = int(xml_parser.parse_int(start_element.get_attribute("length")))
        kind_str = start_element.get_attribute("kind")
        members_only = True
        while element := xml_parser.peek():
            if not isinstance(element, XmlPullParser):
                break
            if element.is_start() and element.get_name().lower() == "member":
                member = PdbXmlMember(xml_parser)
                self.member_list.append(member)
                members_only &= (member.kind == PdbKind.MEMBER)
        xml_parser.end(start_element)

    def __hash__(self):
        return hash(self.name)

    def __eq__(self, other):
        if not isinstance(other, CompositeDefinition):
            return False
        return self.is_class == other.is_class and self.kind == other.kind and self.length == other.length and SymbolUtilities.is_equal(self.name, other.name)
```

Note that this translation is based on the assumption that `PdbParser`, `MessageLog`, `GDirectedGraph`, `DefaultCompositeMember`, `XmlPullParser`, `SymbolPath`, `SystemUtilities` are already defined in Python.