Here is the translation of the given Java code into equivalent Python:

```Python
import xml.etree.ElementTree as ET
from collections import defaultdict

class GroupVertexSerializer:
    GROUP_VERTICES_ELEMENT_NAME = "GROUP_VERTICES"
    REGROUP_VERTICES_ELEMENT_NAME = "REGROUP_VERTICES"

    def __init__(self):
        # factory class--no need to instantiate
        pass

    @staticmethod
    def get_xml_for_regroupable_vertices(function_graph):
        element = ET.Element(GroupVertexSerializer.REGROUP_VERTICES_ELEMENT_NAME)
        group_history = function_graph.get_group_history()
        for info in group_history:
            element.append(info.to_xml(function_graph))
        return element

    @staticmethod
    def get_xml_for_grouped_vertices(function_graph):
        element = ET.Element(GroupVertexSerializer.GROUP_VERTICES_ELEMENT_NAME)
        graph = function_graph.graph
        vertices = list(graph.get_vertices())
        for vertex in vertices:
            if isinstance(vertex, GroupedFunctionGraphVertex):
                info = GroupedVertexInfo((vertex), function_graph)
                element.append(info.to_xml())
        return element

    @staticmethod
    def recreate_group_history(controller, element):
        set = set()
        children = list(element.findall(GroupHistoryInfo.GROUP_HISTORY_ELEMENT_NAME))
        for child in children:
            set.add(GroupHistoryInfo(controller, child))
        return set

    @staticmethod
    def recreate_grouped_vertices(controller, element):
        function_graph_data = controller.get_function_graph_data()
        function_graph = function_graph_data.function_graph
        graph = function_graph.graph
        vertices = list(graph.get_vertices())
        for vertex in vertices:
            if isinstance(vertex, GroupedFunctionGraphVertex):
                return

        children = list(element.findall(GroupedVertexInfo.GROUPED_VERTEX_INFO_ELEMENT_NAME))
        vertex_map = hash_vertices_by_start_and_end_address(function_graph)
        for grouped_vertex_element in children:
            info = GroupedVertexInfo(grouped_vertex_element)
            vertex = info.get_vertex(controller, vertex_map)
            location = info.get_vertex_location()
            install_group_vertex(controller, vertex, location)

    @staticmethod
    def hash_vertices_by_start_and_end_address(function_graph):
        map = defaultdict(dict)
        vertices = list(function_graph.graph.get_ungrouped_vertices())
        for vertex in vertices:
            addresses = set(vertex.addresses)
            min_address = min(addresses)
            max_address = max(addresses)
            map[(min_address, max_address)] = vertex
        return dict(map)

    @staticmethod
    def install_group_vertex(controller, vertex, location):
        if not vertex:
            # can happen when the block model has changed since persisting            
            return

        controller.install_group_vertex(vertex, location)


class GroupHistoryInfo:
    GROUP_HISTORY_ELEMENT_NAME = "GROUP_HISTORY"

    def __init__(self, info, element=None):
        self.info = info
        self.element = element if element else ET.Element(GroupHistoryInfo.GROUP_HISTORY_ELEMENT_NAME)

    @staticmethod
    def to_xml(self):
        return str(self.element)


class GroupedVertexInfo:
    GROUPED_VERTEX_INFO_ELEMENT_NAME = "GROUPED_VERTEX_INFO"

    def __init__(self, vertex_element=None):
        self.vertex_element = vertex_element if vertex_element else ET.Element(GroupedVertexInfo.GROUPED_VERTEX_INFO_ELEMENT_NAME)

    @staticmethod
    def to_xml(self):
        return str(self.vertex_element)


class GroupedFunctionGraphVertex:
    pass


def main():
    # example usage of the class methods
    function_graph = FunctionGraph()
    serializer = GroupVertexSerializer()

    xml_for_regroupable_vertices = serializer.get_xml_for_regroupable_vertices(function_graph)
    print(xml_for_regroupable_vertices)

    xml_for_grouped_vertices = serializer.get_xml_for_grouped_vertices(function_graph)
    print(xml_for_grouped_vertices)


if __name__ == "__main__":
    main()
```

Please note that this translation is not a direct conversion from Java to Python, but rather an equivalent implementation in Python. Some parts of the code may have been modified or reorganized for better readability and compatibility with Python's syntax and semantics.