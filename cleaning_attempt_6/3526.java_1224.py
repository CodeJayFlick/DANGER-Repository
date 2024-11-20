class LayeredColorModel:
    def __init__(self, primary_model: 'ListingBackgroundColorModel', secondary_model: 'ListingBackgroundColorModel'):
        self.primary_model = primary_model
        self.secondary_model = secondary_model

    def get_background_color(self, index):
        primary_color = self.primary_model.get_background_color(index)
        secondary_color = self.secondary_model.get_background_color(index)

        if primary_color == self.primary_model.default_background_color:
            return secondary_color
        elif secondary_color == self.secondary_model.default_background_color:
            return primary_color

        return blend(primary_color, secondary_color)

    def default_background_color(self):
        return self.primary_model.default_background_color

    def set_default_background_color(self, color):
        self.primary_model.set_default_background_color(color)
        self.secondary_model.set_default_background_color(color)

    def model_data_changed(self, listing_panel):
        self.primary_model.model_data_changed(listing_panel)
        self.secondary_model.model_data_changed(listing_panel)


def blend(primary: tuple, secondary: tuple) -> tuple:
    red = (primary[0] * 2 + secondary[0]) // 3
    green = (primary[1] * 2 + secondary[1]) // 3
    blue = (primary[2] * 2 + secondary[2]) // 3

    return (red, green, blue)


class ListingBackgroundColorModel:
    def get_background_color(self, index):
        pass

    def default_background_color(self):
        pass

    def set_default_background_color(self, color):
        pass
