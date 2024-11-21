class ExperimentalLayoutProvider:
    ICON = None

    def __init__(self):
        from resources import ResourceManager
        self.ICON = ResourceManager.load_image("images/package_development.png")

    def get_action_icon(self):
        return self.ICON

    def get_priority_level(self):
        return -100  # below the others
