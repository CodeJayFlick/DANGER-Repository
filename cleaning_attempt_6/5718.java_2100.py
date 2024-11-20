class GhidraApplicationInformationDisplayFactory:
    def __init__(self):
        pass

    def get_window_icons(self):
        icons = []
        for size in [16, 24, 32, 40, 48, 64, 128, 256]:
            icon_path = f"images/GhidraIcon{size}.png"
            try:
                with open(icon_path, 'rb') as file:
                    icon_data = file.read()
                    icons.append((icon_data,))
            except FileNotFoundError:
                pass
        return icons

    def create_splash_screen_title(self):
        return "Welcome To Ghidra"

    def create_about_title(self):
        return "About Ghidra"

    def get_help_location(self):
        help_topics = GenericHelpTopics.ABOUT
        about_topic = "About_Ghidra"
        return HelpLocation(help_topics, about_topic)

    def create_splash_screen_component(self):
        from InfoPanel import InfoPanel  # Assuming this is a separate class/file
        return InfoPanel()

    def get_home_icon(self):
        icon_path = "images/GhidraIcon16.png"
        try:
            with open(icon_path, 'rb') as file:
                icon_data = file.read()
                return ImageIcon(icon_data)
        except FileNotFoundError:
            pass

    def get_home_callback(self):
        def callback():
            front_end_tool = AppInfo.get_front_end_tool()
            front_end_tool.to_front()

        return callback
