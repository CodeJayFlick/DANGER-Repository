import xml.etree.ElementTree as ET
from io import StringIO
import os
import sys

class StandAloneApplication:
    DEFAULT_TOOL_NAME = "DefaultTool.tool"
    SAVED_TOOL_FILE = "SavedTool(tool"

    def __init__(self, properties_filename):
        self.layout = DockingApplicationLayout(read_application_properties(properties_filename))
        self.configuration = new_DockingApplicationConfiguration()
        self.display_factory = SettableApplicationInformationDisplayFactory()

    @staticmethod
    def read_application_properties(properties_filename) -> dict:
        try:
            with open(properties_filename, 'r') as f:
                properties = {}
                for line in f.readlines():
                    key, value = line.strip().split('=')
                    properties[key] = value
                return properties
        except Exception as e:
            print(f"Error reading application properties: {e}")
            sys.exit(0)

    def init(self, application_layout):
        self.layout = application_layout

        # Setup application configuration
        self.configuration.set_show_splash_screen(False)
        self.display_factory = SettableApplicationInformationDisplayFactory()

    def show_spash_screen(self, splash_icon) -> None:
        self.configuration.set_show_splash_screen(True)
        self.display_factory.set_splash_icon(splash_icon)

    def set_windows_icons(self, windows_icons: list[ET.Element]) -> None:
        self.display_factory.set_windows_icons(windows_icons)

    def set_home_icon(self, icon: ET.Element) -> None:
        self.display_factory.set_home_icon(icon)

    def set_home_callback(self, callback: callable) -> None:
        self.display_factory.set_home_callback(callback)

    def start(self):
        PluggableServiceRegistry.register_pluggable_service(ApplicationInformationDisplayFactory(), self.display_factory)
        Application.initialize_application(self.layout, self.configuration)
        try:
            ClassSearcher.search(self.configuration.get_task_monitor())
        except CancelledException as e:
            print(f"Class searching unexpectedly cancelled: {e}")

        set_dock_icon()

        try:
            tool = create_tool()
        except Exception as e:
            print(f"Error creating tool, exiting...: {e}")
            sys.exit(0)

        show_tool(tool)

    def show_tool(self) -> None:
        self.tool.set_visible(True)

    @staticmethod
    def set_dock_icon() -> None:
        if Taskbar.is_taskbar_supported():
            taskbar = Taskbar.get_taskbar()
            if taskbar.is_supported(Taskbar.Feature.ICON_IMAGE):
                taskbar.set_icon_image(ApplicationInformationDisplayFactory().get_largest_window_icon())

    def create_tool(self) -> PluginTool:
        new_tool = StandAlonePluginTool(self, self.layout.application_properties['application.name'], True)

        root_element = get_saved_tool_element()
        if root_element is None:
            root_element = get_default_tool_element()

        if root_element is not None:
            tool_element = root_element.find('TOOL')
            saved_data_element = root_element.find('DATA_STATE')

            self.configuration.get_task_monitor().set_message("Restoring Tool Configuration...")
            new_tool.restore_from_xml(tool_element)
            self.configuration.get_task_monitor().set_message("Restoring Tool State...")
            new_tool.restore_data_state_from_xml(saved_data_element)

        initialize_tool(new_tool)
        return new_tool

    @staticmethod
    def get_default_tool_element() -> ET.Element:
        try:
            with open(ResourceManager().get_resourceAsStream(DEFAULT_TOOL_NAME), 'r') as f:
                sax = XmlUtilities.create_secure_sax_builder(False, False)
                root = sax.build(StringIO(f.read())).getroot()
                return root
        except Exception as e:
            print(f"Error reading tool: {e}")

    @staticmethod
    def get_saved_tool_element() -> ET.Element | None:
        saved_tool_file = os.path.join(Application().get_user_settings_directory(), SAVED_TOOL_FILE)
        if not os.path.exists(saved_tool_file):
            return None

        try:
            with open(saved_tool_file, 'r') as f:
                sax = XmlUtilities.create_secure_sax_builder(False, False)
                root = sax.build(StringIO(f.read())).getroot()
                return root
        except Exception as e:
            print(f"Error reading tool: {e}")

    def exit(self) -> None:
        self.tool.close()

class ToolServicesAdapter:
    @staticmethod
    def close_tool(t: PluginTool):
        sys.exit(0)

    @staticmethod
    def save_tool(save_tool: PluginTool) -> ET.Element | None:
        try:
            tool_element = save_tool.save_to_xml(True)
            data_state_element = save_tool.save_data_state_to_xml(False)
            root_element = ET.Element('Root')
            root_element.append(tool_element)
            root_element.append(data_state_element)

            saved_tool_file = os.path.join(Application().get_user_settings_directory(), SAVED_TOOL_FILE)
            with open(saved_tool_file, 'w') as f:
                ET.tostring(root_element, encoding='unicode').encode(f.write())

        except Exception as e:
            print(f"Error saving tool: {e}")

class DockingApplicationLayout:
    def __init__(self, application_properties):
        self.application_properties = application_properties

class SettableApplicationInformationDisplayFactory:
    pass

class PluginTool:
    def close(self) -> None:
        sys.exit(0)

    @staticmethod
    def restore_from_xml(tool_element: ET.Element | None) -> None:
        if tool_element is not None:
            # Restore from XML here...
            pass

    @staticmethod
    def save_to_xml(save_data_state: bool) -> ET.Element | None:
        try:
            root = ET.Element('TOOL')
            return root
        except Exception as e:
            print(f"Error saving tool to XML: {e}")

class Application:
    @staticmethod
    def get_user_settings_directory() -> str:
        pass

    @staticmethod
    def initialize_application(application_layout, configuration) -> None:
        # Initialize application here...
        pass

    @staticmethod
    def run_swing_now(callback: callable):
        try:
            callback()
        except Exception as e:
            print(f"Error running Swing now: {e}")

class ResourceManager:
    @staticmethod
    def get_resourceAsStream(resource_name) -> str | None:
        return DEFAULT_TOOL_NAME

class SystemUtilities:
    @staticmethod
    def run_swing_now(callback: callable):
        try:
            callback()
        except Exception as e:
            print(f"Error running Swing now: {e}")

if __name__ == "__main__":
    application = StandAloneApplication("properties_file")
    application.start()

