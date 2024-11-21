import unittest
from ghidra.framework.main import *
from docking.action.dockingactionif import DockingActionIf
from generic.test.abstractgenerictest import AbstractGenericTest
from utilities.util.fileutilities import FileUtilities
from server.remote.serveradapter import ServerAdapter

class NewProjectWizardTest(unittest.TestCase):

    def setUp(self):
        self.env = TestEnv()
        project_directory = GenericRunInfo.get_projects_dir_path()
        delete_project(project_directory, "ProjectTest")
        
        # Note: we must call clear() on the preferences, and not delete the file, since
        # the preferences have already been loaded at this point.  Also, even if you deleted 
        # the file before the data was loaded, then the preferences would simply load from 
        # another directory.
        
        Preferences.clear()
        
        self.front_end_tool = self.env.get_front_end_tool()
        self.env.show_front_end_tool()

    def tearDown(self):
        try:
            save_action = get_action("Save Project")
            perform_action(save_action, True)
            action = get_action("Close Project")
            perform_action(action, True)

            project_directory = GenericRunInfo.get_projects_dir_path()

            delete_project(project_directory, "ProjectTest")

        finally:
            self.env.dispose()
            
            try:
                Preferences.set_property("ServerInfo", None)
                Preferences.store()
            except Exception as e:
                print(f"Error: {e}")

    def test_create_non_shared_project(self):
        try:
            start_server()

            action = get_action("New Project")
            perform_action(action, False)

            wizard_manager = self.env.get_wizard_manager()
            
            assert isinstance(wizard_manager, WizardManager)
            
            project_type_panel = find_component(wizard_manager, "ProjectTypePanel", 2000)
            assert isinstance(project_type_panel, ProjectTypePanel)
            
            radio_button = find_abstract_button_by_text(project_type_panel, "Non-Shared Project")
            assert isinstance(radio_button, JRadioButton)
            self.assertTrue(radio_button.isSelected())

            next_button = find_button_by_text(wizard_manager, "Next >>")
            assert isinstance(next_button, JButton)
            self.assertTrue(next_button.isEnabled())
            
            finish_button = find_button_by_text(wizard_manager, "Finish")
            assert isinstance(finish_button, JButton)
            self.assertFalse(finish_button.isEnabled())

            press_button(next_button)

            select_project_panel = find_component(wizard_manager, "SelectProjectPanel", 2000)
            assert isinstance(select_project_panel, SelectProjectPanel)
            
            directory_field = find_component_by_name(select_project_panel, "Project Directory")
            project_field = find_component_by_name(select_project_panel, "Project Name")

            self.assertTrue(directory_field.getText().length() > 0)

            final_text = SwingUtilities.invokeLater(lambda: f"{directory_field.getText()} {project_field.getText()}")
            
            finish_button.setEnabled(final_text in select_project_panel.getStatusMessage())

            press_button(finish_button)
            time.sleep(500)
            perform_action(finish_button, True)

        except Exception as e:
            print(f"Error: {e}")

    def test_create_non_shared_project2(self):
        try:
            start_server()

            action = get_action("New Project")
            perform_action(action, False)

            wizard_manager = self.env.get_wizard_manager()
            
            assert isinstance(wizard_manager, WizardManager)
            
            project_type_panel = find_component(wizard_manager, "ProjectTypePanel", 2000)
            assert isinstance(project_type_panel, ProjectTypePanel)
            
            radio_button = find_abstract_button_by_text(project_type_panel, "Non-Shared Project")
            assert isinstance(radio_button, JRadioButton)
            self.assertTrue(radio_button.isSelected())

            next_button = find_button_by_text(wizard_manager, "Next >>")
            assert isinstance(next_button, JButton)
            self.assertTrue(next_button.isEnabled())
            
            finish_button = find_button_by_text(wizard_manager, "Finish")
            assert isinstance(finish_button, JButton)
            self.assertFalse(finish_button.isEnabled())

            press_button(next_button)

            select_project_panel = find_component(wizard_manager, "SelectProjectPanel", 2000)
            assert isinstance(select_project_panel, SelectProjectPanel)
            
            directory_field = find_component_by_name(select_project_panel, "Project Directory")
            project_field = find_component_by_name(select_project_panel, "Project Name")

            self.assertTrue(directory_field.getText().length() > 0)

            final_text = SwingUtilities.invokeLater(lambda: f"{directory_field.getText()} {project_field.getText()}")
            
            finish_button.setEnabled(final_text in select_project_panel.getStatusMessage())

            press_button(finish_button)
            time.sleep(500)
            perform_action(finish_button, True)

        except Exception as e:
            print(f"Error: {e}")

    def test_create_shared_project(self):
        try:
            start_server()

            action = get_action("New Project")
            perform_action(action, False)

            wizard_manager = self.env.get_wizard_manager()
            
            assert isinstance(wizard_manager, WizardManager)
            
            project_type_panel = find_component(wizard_manager, "ProjectTypePanel", 2000)
            assert isinstance(project_type_panel, ProjectTypePanel)
            
            radio_button = find_abstract_button_by_text(project_type_panel, "Shared Project")
            assert isinstance(radio_button, JRadioButton)
            self.assertFalse(radio_button.isSelected())

            SwingUtilities.invokeLater(lambda: radio_button.setSelected(True))

            next_button = find_button_by_text(wizard_manager, "Next >>")
            assert isinstance(next_button, JButton)
            self.assertTrue(next_button.isEnabled())
            
            finish_button = find_button_by_text(wizard_manager, "Finish")
            assert isinstance(finish_button, JButton)
            self.assertFalse(finish_button.isEnabled())

            press_button(next_button)

            server_info_panel = find_component(wizard_manager, "ServerInfoPanel", 2000)
            assert isinstance(server_info_panel, ServerInfoPanel)
            
            server_field = find_component_by_name(server_info_panel, "Server Name")
            port_number_field = find_component_by_name(server_info_panel, "Port Number")

            self.assertTrue(server_field.getText().length() > 0)

            SwingUtilities.invokeLater(lambda: f"{LOCALHOST} {SERVER_PORT}")

            next_button.setEnabled(final_text in server_info_panel.getStatusMessage())

            press_button(next_button)

            repository_panel = find_component(wizard_manager, "RepositoryPanel", 2000)
            assert isinstance(repository_panel, RepositoryPanel)
            
            existing_radio_button = find_abstract_button_by_text(repository_panel, "Existing Repository")
            assert isinstance(existing_radio_button, JRadioButton)
            self.assertTrue(existing_radio_button.isSelected())

            create_radio_button = find_abstract_button_by_text(repository_panel, "Create Repository")
            assert isinstance(create_radio_button, JRadioButton)
            self.assertFalse(create_radio_button.isSelected())
            
            rep_name_field = find_component_by_name(repository_panel, "Repository Name")

            SwingUtilities.invokeLater(lambda: f"{rep_name_field.getText()} {LOCALHOST} {SERVER_PORT}")

            finish_button.setEnabled(final_text in repository_panel.getStatusMessage())

            press_button(finish_button)
            time.sleep(500)
            perform_action(finish_button, True)

        except Exception as e:
            print(f"Error: {e}")

    def test_create_shared_project_existing(self):
        try:
            start_server()

            action = get_action("New Project")
            perform_action(action, False)

            wizard_manager = self.env.get_wizard_manager()
            
            assert isinstance(wizard_manager, WizardManager)
            
            project_type_panel = find_component(wizard_manager, "ProjectTypePanel", 2000)
            assert isinstance(project_type_panel, ProjectTypePanel)
            
            radio_button = find_abstract_button_by_text(project_type_panel, "Shared Project")
            assert isinstance(radio_button, JRadioButton)
            self.assertFalse(radio_button.isSelected())

            SwingUtilities.invokeLater(lambda: radio_button.setSelected(True))

            next_button = find_button_by_text(wizard_manager, "Next >>")
            assert isinstance(next_button, JButton)
            self.assertTrue(next_button.isEnabled())
            
            finish_button = find_button_by_text(wizard_manager, "Finish")
            assert isinstance(finish_button, JButton)
            self.assertFalse(finish_button.isEnabled())

            press_button(next_button)

            server_info_panel = find_component(wizard_manager, "ServerInfoPanel", 2000)
            assert isinstance(server_info_panel, ServerInfoPanel)
            
            server_field = find_component_by_name(server_info_panel, "Server Name")
            port_number_field = find_component_by_name(server_info_panel, "Port Number")

            self.assertTrue(server_field.getText().length() > 0)

            SwingUtilities.invokeLater(lambda: f"{LOCALHOST} {SERVER_PORT}")

            next_button.setEnabled(final_text in server_info_panel.getStatusMessage())

            press_button(next_button)

            repository_panel = find_component(wizard_manager, "RepositoryPanel", 2000)
            assert isinstance(repository_panel, RepositoryPanel)
            
            existing_radio_button = find_abstract_button_by_text(repository_panel, "Existing Repository")
            assert isinstance(existing_radio_button, JRadioButton)
            self.assertTrue(existing_radio_button.isSelected())

            create_radio_button = find_abstract_button_by_text(repository_panel, "Create Repository")
            assert isinstance(create_radio_button, JRadioButton)
            self.assertFalse(create_radio_button.isSelected())
            
            rep_name_field = find_component_by_name(repository_panel, "Repository Name")

            SwingUtilities.invokeLater(lambda: f"{rep_name_field.getText()} {LOCALHOST} {SERVER_PORT}")

            finish_button.setEnabled(final_text in repository_panel.getStatusMessage())

            press_button(finish_button)
            time.sleep(500)
            perform_action(finish_button, True)

        except Exception as e:
            print(f"Error: {e}")

    def start_server(self):
        parent = File(GenericRunInfo.get_test_directory_path())
        
        # Create server instance
        self.server_root = File(parent, "My_Server")
        if not self.server_root.exists():
            self.server_root.mkdir()

        repository_adapter = ServerTestUtil.get_server_adapter(self.server_root, [USER])
        
        if repository_adapter is None or not repository_adapter.is_connected():
            ServerTestUtil.dispose_server()
            FileUtilities.delete_dir(self.server_root)
            self.server_root = None
            raise Exception("Server connect failed")

    def get_action(self, action_name):
        return DockingActionIf(action=self.front_end_tool.get_front_end_plugin(), name=action_name)

    def find_component(self, wizard_manager, component_type, timeout=2000):
        for i in range(timeout // 10):
            if isinstance(wizard_manager.getComponent(i), component_type):
                return wizard_manager.getComponent(i)
            time.sleep(100)
        raise Exception(f"Component {component_type} not found")

    def find_abstract_button_by_text(self, panel, text):
        for button in panel.getComponents():
            if isinstance(button, JRadioButton) and button.getText() == text:
                return button
        raise Exception(f"Button with text '{text}' not found")

    def find_component_by_name(self, panel, name):
        for component in panel.getComponents():
            if hasattr(component, 'getName') and component.getName() == name:
                return component
        raise Exception(f"Component with name {name} not found")

    def press_button(self, button):
        SwingUtilities.invokeLater(lambda: self.env.show_front_end_tool())

    def perform_action(self, action, wait=False):
        if isinstance(action, DockingActionIf):
            self.front_end_tool.get_front_end_plugin().perform_action(action)
        elif isinstance(action, JButton) and action.isEnabled():
            SwingUtilities.invokeLater(lambda: action.doClick())
        else:
            raise Exception(f"Invalid action {action}")

    def delete_project(self, project_directory, name):
        file = File(project_directory.getAbsolutePath(), f"{name}.ghidra")
        if file.exists():
            file.delete()
