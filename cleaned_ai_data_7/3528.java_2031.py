class MarkerServiceBackgroundColorModel:
    def __init__(self, marker_service: 'MarkerService', program=None, index_map=None):
        self.marker_service = marker_service
        self.program = program
        self.index_map = index_map
        self.default_background_color = (255, 255, 255)  # WHITE

    @property
    def default_background_color(self):
        return self._default_background_color

    @default_background_color.setter
    def default_background_color(self, value: tuple):
        self._default_background_color = value

    def get_background_color(self, index: int) -> tuple:
        addr = self.index_map.get_address(index)
        color = None
        if addr is not None:
            if self.program is None:
                color = self.marker_service.get_background_color(addr)
            else:
                color = self.marker_service.get_background_color(self.program, addr)
        if color is None:
            color = self.default_background_color
        return color

    def model_data_changed(self, listing_panel: 'ListingPanel'):
        self.program = listing_panel.get_program()
        self.index_map = listing_panel.get_address_index_map()

class MarkerService:
    # assume this class has methods get_background_color and other necessary functions

# usage example
marker_service = MarkerService()  # create an instance of the MarkerService class
program = Program()  # create an instance of the Program class
index_map = AddressIndexMap()  # create an instance of the AddressIndexMap class

model = MarkerServiceBackgroundColorModel(marker_service, program, index_map)
print(model.get_background_color(0))  # get the background color for a given address
