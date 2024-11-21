class MultiBlendedListingBackgroundColorModel:
    def __init__(self):
        self.models = []
        self.blender = None

    def add_model(self, model):
        self.models.append(model)

    def remove_model(self, model):
        if model in self.models:
            self.models.remove(model)

    def get_background_color(self, index):
        self.blender.clear()
        for m in self.models:
            c = m.get_background_color(index)
            if c is None:
                continue
            elif c == m.default_background_color:
                continue
            self.blender.add(c)
        return self.blender.color(default_background_color)

    def get_default_background_color(self):
        if not self.models:
            return (255, 255, 255)  # white
        else:
            return self.models[0].default_background_color

    def set_default_background_color(self, c):
        for m in self.models:
            m.set_default_background_color(c)

    def model_data_changed(self, listing_panel):
        for m in self.models:
            if isinstance(m, ListingBackgroundColorModel):
                lm = m
                lm.model_data_changed(listing_panel)
