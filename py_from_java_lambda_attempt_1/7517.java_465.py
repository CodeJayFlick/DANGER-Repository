Here is the translation of the Java code into Python:

```Python
class GroupHistoryInfo:
    GROUP_HISTORY_ELEMENT_NAME = "GROUP_ HISTORY"
    GROUP_DESCRIPTION_ATTRIBUTE = "GROUP_DESCRIPTION"

    def __init__(self, function_graph, group_vertex):
        self.group_vertices = set(group_vertex.get_vertices())
        if not self.group_vertices:
            raise ValueError("Cannot create a group history entry with no vertices!")

        self.group_description = group_vertex.get_user_text()
        if not self.group_description:
            raise ValueError("Group description cannot be null")

        graph_layout = function_graph.get_layout()
        location = graph_layout.apply(group_vertex)
        self.location_info = PointInfo(location)

        self.address_info = AddressInfo(group_vertex)

    def __init__(self, controller, element):
        fg_data = controller.get_function_graph_data()
        function_graph = fg_data.get_function_graph()

        vertex_map = {}
        for child in element.children():
            if child.tag == VertexInfo.VERTEX_INFO_ELEMENT_NAME:
                vertex_info = VertexInfo(child)
                vertex = vertex_info.get_vertex(controller, vertex_map)
                if vertex is not None:
                    self.group_vertices.add(vertex)

            elif child.tag == GroupedVertexInfo.GROUPED_VERTEX_INFO_ELEMENT_NAME:
                grouped_vertex_info = GroupedVertexInfo(child)
                vertex = grouped_vertex_info.locate_vertex(controller, vertex_map)
                if vertex is not None:
                    self.group_vertices.add(vertex)

        escaped_group_description = element.get_attribute_value(GROUP_DESCRIPTION_ATTRIBUTE)
        group_description = XmlUtilities.unescape_element_entities(escaped_group_description)

        self.group_description = group_description

        address_info_element = element.find(AddressInfo.VERTEX_ADDRESS_INFO_ELEMENT_NAME)
        if address_info_element is not None:
            self.address_info = AddressInfo(address_info_element)

        location_info_element = element.find(VertexInfo.LOCATION_INFO_ELEMENT_NAME)
        point_info_element = location_info_element.find(PointInfo.POINT_INFO_ELEMENT_NAME)
        if point_info_element is not None:
            self.location_info = PointInfo(point_info_element)

    def set_group_description(self, text):
        self.group_description = text
        for vertex in self.group_vertices.copy():
            vertex.update_group_association_status(self)

    def contains(self, vertex):
        for child_vertex in self.group_vertices:
            if matches_or_contains(child_vertex, vertex):
                return True

        return False

    @staticmethod
    def matches_or_contains(potential_match, vertex):
        if potential_match == vertex:
            return True

        if isinstance(potential_match, GroupedFunctionGraphVertex):
            for child in potential_match.get_vertices():
                if matches_or_contains(child, vertex):
                    return True

        return False

    def remove_vertex(self, vertex):
        self.update_group_description(vertex)

        self.group_vertices.remove(vertex)

        # also fixup any internal groups that may contain the given vertex
        self.remove_from_groups(vertex)

    @staticmethod
    def update_group_description(vertex):
        text = GroupedFunctionGraphVertex.get_vertex_description(vertex)
        index = group_description.find(text)
        if index != -1:
            buffy = StringBuffer(group_description)
            buffy.delete(index, index + len(text))
            group_description = buffy.toString()

    @staticmethod
    def remove_from_groups(old_vertex):
        vertices = set(self.group_vertices)

        for vertex in vertices.copy():
            if isinstance(vertex, GroupedFunctionGraphVertex) and old_vertex in vertex.get_vertices():
                new_group = removeFromGroup(old_vertex, vertex)
                if new_group is not None:
                    self.group_vertices.remove(vertex)
                    self.group_vertices.add(new_group)

    @staticmethod
    def remove_from_group(old_vertex, group):
        to_remove = set()

        for child in group.get_vertices().copy():
            if child == old_vertex:
                to_remove.add(child)

            elif isinstance(child, GroupedFunctionGraphVertex):
                new_group = removeFromGroup(old_vertex, child)
                if new_group is not None:
                    self.group_vertices.remove(group)
                    self.group_vertices.add(new_group)

        return group.remove_all(to_remove)

    def get_group_location(self):
        return self.location_info.get_point()

    @property
    def vertices(self):
        return frozenset(self.group_vertices)

    @property
    def group_description(self):
        return self._group_description

    def to_xml(self, function_graph):
        element = Element(GroupHistoryInfo.GROUP_HISTORY_ELEMENT_NAME)

        for vertex in self.group_vertices:
            if isinstance(vertex, GroupedFunctionGraphVertex):
                vertex_info = GroupedVertexInfo(vertex, function_graph)
                element.append(vertex_info.to_xml())

            else:
                vertex_info = VertexInfo(vertex, function_graph)
                element.append(vertex_info.to_xml())

        escaped_text = XmlUtilities.escape_element_entities(self.group_description)
        element.set_attribute(GroupHistoryInfo.GROUP_DESCRIPTION_ATTRIBUTE, escaped_text)

        self.address_info.write(element)

        location_element = Element(VertexInfo.LOCATION_INFO_ELEMENT_NAME)
        self.location_info.write(location_element)
        element.append(location_element)

        return element

    def __str__(self):
        return f"text=\"{self.group_description}\", AddressInfo={self.address_info}, location={self.location_info}"

class PointInfo:
    @staticmethod
    def from_xml(element):
        point = None
        for child in element.children():
            if child.tag == "x" or child.tag == "y":
                value = float(child.text)
                if not hasattr(PointInfo, 'point'):
                    setattr(PointInfo, 'point', Point2D())
                getattr(PointInfo, 'point').set_x(value) if child.tag == "x" else getattr(PointInfo, 'point').set_y(value)

        return self

    def __init__(self, location):
        self.point = Point2D()
        self.point.set_x(location.x)
        self.point.set_y(location.y)

class AddressInfo:
    @staticmethod
    def from_xml(element):
        min_address = None
        max_address = None
        for child in element.children():
            if child.tag == "min" or child.tag == "max":
                value = int(child.text)
                if child.tag == "min":
                    min_address = Address(value, 0)
                else:
                    max_address = Address(0, value)

        return self

    def __init__(self, vertex):
        self.min_address = vertex.get_min_address()
        self.max_address = vertex.get_max_address()

class VertexInfo:
    @staticmethod
    def from_xml(element):
        pass

    def __init__(self, vertex, function_graph):
        if isinstance(vertex, GroupedFunctionGraphVertex):
            self.vertex = None
        else:
            self.vertex = vertex

def removeFromGroup(old_vertex, group):
    to_remove = set()

    for child in group.get_vertices().copy():
        if child == old_vertex:
            to_remove.add(child)

        elif isinstance(child, GroupedFunctionGraphVertex):
            new_group = removeFromGroup(old_vertex, child)
            if new_group is not None:
                return new_group

    return group.remove_all(to_remove)