class VertexInfo:
    VERTEX_INFO_ELEMENT_NAME = "VERTEX_INFO"
    LOCATION_INFO_ELEMENT_NAME = "LOCATION_POINT_INFO"

    def __init__(self, vertex, function_graph):
        self.vertex_address_info = AddressInfo(vertex)
        graph_layout = function_graph.get_layout()
        location = graph_layout.apply(vertex)
        self.location_info = PointInfo(location)

    @classmethod
    def from_element(cls, element):
        vertex_info_element = element.getChild(VERTEX_INFO_ELEMENT_NAME)
        address_info = AddressInfo.from_element(vertex_info_element)
        location_element = element.getChild(LOCATION_INFO_ELEMENT_NAME)
        point_info_element = location_element.getChild(PointInfo.POINT_INFO_ELEMENT_NAME)
        return cls(address_info.get_vertex(), None, vertex_info=vertex_info_element)

    def __str__(self):
        return f"{type(self).__name__}[AddressInfo={self.vertex_address_info}, location={self.location_info}]"

    @classmethod
    def get_vertex(cls, controller, vertex_map, address_info):
        program = controller.get_program()
        address_factory = program.get_address_factory()
        min_address = address_factory.get_address(address_info.address_range_start)
        max_address = address_factory.get_address(address_info.address_range_end)
        address_hasher = AddressHasher(min_address, max_address)
        vertex = vertex_map.get(address_hasher)
        if vertex is None:
            return None
        vertex.set_location(cls.get_vertex_location(self))
        return vertex

    @classmethod
    def get_vertex_location(cls, self):
        return self.location_info.get_point()

    def get_in_edges(self, controller, vertex):
        edges = set()
        function_graph_data = controller.get_function_graph_data()
        function_graph = function_graph_data.get_function_graph()
        graph = function_graph
        in_edges = graph.get_in_edges(vertex)
        if in_edges is None:
            return None
        for edge in in_edges:
            edges.add(edge)
        return edges

    def get_out_edges(self, controller, vertex):
        edges = set()
        function_graph_data = controller.get_function_graph_data()
        function_graph = function_graph_data.get_function_graph()
        graph = function_graph
        out_edges = graph.get_out_edges(vertex)
        if out_edges is None:
            return None
        for edge in out_edges:
            edges.add(edge)
        return edges

    def to_xml(self):
        vertex_info_element = Element(VERTEX_INFO_ELEMENT_NAME)

        # sub-tags: 
        # - address info
        # - location
        # - edge infos
        # -- address info
        # -- flow type
        # -- articulation points
        self.vertex_address_info.write(vertex_info_element)
        
        location_element = Element(self.LOCATION_INFO_ELEMENT_NAME)
        self.location_info.write(location_element)
        vertex_info_element.add_content(location_element)

        return vertex_info_element

class AddressInfo:
    def __init__(self, address):
        self.address_range_start = address
        self.address_range_end = address

    @classmethod
    def from_element(cls, element):
        # implementation of this method is missing in the original Java code
        pass

    def write(self, vertex_info_element):
        # implementation of this method is missing in the original Java code
        pass

class PointInfo:
    POINT_INFO_ELEMENT_NAME = "POINT_INFO"

    @classmethod
    def from_element(cls, element):
        # implementation of this method is missing in the original Java code
        pass

    def write(self, location_element):
        # implementation of this method is missing in the original Java code
        pass

class AddressHasher:
    def __init__(self, min_address, max_address):
        self.min_address = min_address
        self.max_address = max_address

    @classmethod
    def from_min_max(cls, min_address, max_address):
        # implementation of this method is missing in the original Java code
        pass
