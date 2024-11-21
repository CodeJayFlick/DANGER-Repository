class AddressInfo:
    START_ADDRESS = "START_ADDRESS"
    END_ADDRESS = "END_ADDRESS"
    VERTEX_ADDRESS_INFO_ELEMENT_NAME = "VERTEX_ADDRESS_INFO"

    def __init__(self, vertex=None):
        if vertex is None:
            raise ValueError("Vertex cannot be null")
        addresses = vertex.get_addresses()
        self.address_range_start = str(addresses.min_address)
        self.address_range_end = str(addresses.max_address)

    @classmethod
    def from_element(cls, element):
        address_info = cls(None)  # Initialize with None to avoid errors
        address_info.address_range_start = element.getAttribute(START_ADDRESS)
        address_info.address_range_end = element.getAttribute(END_ADDRESS)
        if not address_info.address_range_start:
            raise ValueError(f"Error reading XML for {cls.__name__}")
        if not address_info.address_range_end:
            raise ValueError(f"Error reading XML for {cls.__name__}")
        return address_info

    def write(self, parent):
        element = Element(VERTEX_ADDRESS_INFO_ELEMENT_NAME)
        element.set_attribute(START_ADDRESS, self.address_range_start)
        element.set_attribute(END_ADDRESS, self.address_range_end)
        parent.add_content(element)

    def __str__(self):
        return f"{self.__class__.__name__}[start={self.address_range_start}, end={self.address_range_end}]"
