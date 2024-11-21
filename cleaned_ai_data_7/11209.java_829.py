class ToolTemplate:
    TOOL_XML_NAME = "TOOL"
    TOOL_NAME_XML_NAME = "TOOL_NAME"
    TOOL_INSTANCE_NAME_XML_NAME = "INSTANCE_NAME"

    def __init__(self):
        self.name = None
        self.path = None

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        self._name = value

    @property
    def path(self):
        return self._path

    @path.setter
    def path(self, value):
        self._path = value

    def get_icon_url(self):
        # This method should be implemented in the subclass.
        pass

    def get_icon(self):
        icon_url = self.get_icon_url()
        if icon_url:
            return ImageIcon(icon_url)
        else:
            return None

    def get_supported_data_types(self):
        # This method should be implemented in the subclass.
        pass

    def save_to_xml(self):
        # This method should be implemented in the subclass.
        pass

    def restore_from_xml(self, root):
        # This method should be implemented in the subclass.
        pass

    def create_tool(self, project):
        # This method should be implemented in the subclass.
        pass

    def get_tool_element(self):
        # This method should be implemented in the subclass.
        pass
