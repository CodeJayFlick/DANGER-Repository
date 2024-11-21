class GhidraToolTemplate:
    CLASS_NAME_XML_NAME = "CLASS_NAME"
    LOCATION_XML_NAME = "LOCATION"
    ICON_XML_NAME = "ICON"

    TEMPLATE_NAME = "Ghidra_Tool_Template"

    def __init__(self, root: dict, path: str):
        self.path = path
        self.restore_from_xml(root)

    @classmethod
    def from_icon_url(cls, icon_url: ToolIconURL, tool_element: Element, supported_data_types: list) -> 'GhidraToolTemplate':
        return cls(None, None, icon_url, tool_element, supported_data_types)

    def __init__(self, root=None, path=None, icon_url=None, tool_element=None, supported_data_types=None):
        if root is not None:
            self.restore_from_xml(root)
        else:
            self.path = path
            self.icon_url = icon_url
            self.tool_element = tool_element
            self.supported_data_types = supported_data_types

    def get_name(self) -> str:
        return self.tool_element.get_attribute_value(GhidraToolTemplate.CLASS_NAME_XML_NAME)

    def get_path(self) -> str:
        return self.path

    def set_name(self, name: str):
        self.tool_element.set_attribute(GhidraToolTemplate.CLASS_NAME_XML_NAME, name)

    def get_icon(self) -> ImageIcon:
        return self.icon_url.get_icon()

    def get_supported_data_types(self) -> list:
        return self.supported_data_types

    def get_icon_url(self) -> ToolIconURL:
        return self.icon_url

    def __hash__(self):
        return hash(self.get_name())

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, GhidraToolTemplate):
            return False
        if id(self) == id(other):
            return True
        if type(self).__class__ != type(other).__class__:
            return False

        return self.get_name() == other.get_name()

    def __str__(self) -> str:
        return f"{self.get_name()} - {self.path}"

    @classmethod
    def restore_from_xml(cls, root: dict):
        supported_data_types = []
        for elem in root["SUPPORTED_DATA_TYPE"]:
            class_name = elem[cls.CLASS_NAME_XML_NAME]
            try:
                dt_list.append(Class.forName(class_name))
            except ClassNotFoundException as e:
                Msg.error(self, f"Class not found: {class_name}", e)
            except Exception as exc:
                # TODO
                Msg.error(self, f"Unexpected Exception: {exc.message}", exc)

        supported_data_types = [dt for dt in dt_list]

    @classmethod
    def save_to_xml(cls):
        root = {"TOOL_CONFIG": {}}
        for supported_datatype in cls.supported_data_types:
            elem = {"SUPPORTED_DATA_TYPE": []}
            elem[cls.CLASS_NAME_XML_NAME] = supported_datatype.name()
            root["TOOL_CONFIG"].add_content(elem)

    def set_icon_url(self, url: ToolIconURL):
        self.icon_url = url

    @classmethod
    def get_tool_element(cls) -> Element:
        return cls.tool_element

    @classmethod
    def create_tool(cls, project: Project) -> PluginTool:
        return GhidraTool(project, this)
