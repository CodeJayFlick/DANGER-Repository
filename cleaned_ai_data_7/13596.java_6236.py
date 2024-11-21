import os
from typing import List

class ExportGhidraModuleWizard:
    def __init__(self):
        self.project_page = None
        self.gradle_page = None

    def init(self, selection: object) -> None:
        project_path = GhidraProjectUtils.get_selected_project(selection)
        self.project_page = ChooseGhidraModuleProjectWizardPage(project_path)
        self.gradle_page = ConfigureGradleWizardPage(self.project_page)

    def add_pages(self):
        self.add_page(self.project_page)
        self.add_page(self.gradle_page)

    def perform_finish(self) -> bool:
        java_project = self.project_page.get_ghidra_module_project()
        gradle_distribution = self.gradle_page.get_gradle_distribution()

        try:
            export(java_project, gradle_distribution)
        except Exception as e:
            error(f"Error: {e}")
            return False

        return True


def export(java_project: object, gradle_distribution: str) -> None:
    project_path = java_project.get_location()
    ghidra_install_dir_path = os.path.join(project_path, GhidraProjectUtils.GHIDRA_FOLDER_NAME)
    
    try:
        # Get path to Ghidra installation directory
        ghidra_install_dir_path = os.path.abspath(ghidra_install_dir_path)

        # Get project's java.  Gradle should use the same version.
        ghidra_layout = GhidraApplicationLayout(os.path.join(ghidra_install_dir_path, "Ghidra"))
        java_home_dir = JavaConfig(ghidra_layout.get_application_installation_dir()).get_saved_java_home()
        
        if not os.path.exists(java_home_dir):
            raise IOException("Failed to get the Java home associated with the project.  Perform a 'Link Ghidra' operation on the project and try again.")

        # Setup the Gradle build attributes
        tasks = []
        working_dir = os.path.abspath(project_path)
        gradle_dist = gradle_distribution
        java_home = os.path.join(java_home_dir, "bin")
        jvm_args = []
        gradle_args = [f"-PGHIDRA_INSTALL_DIR={ghidra_install_dir_path}"]
        show_execution_view = False
        show_console_view = True
        override_workspace_settings = True
        is_offline = True
        is_build_scans_enabled = False

        # Launch Gradle
        gradle_launch_configuration_manager = CorePlugin.gradle_launch_configuration_manager()
        launch_configuration = gradle_launch_configuration_manager.get_or_create_run_configuration(
            tasks, working_dir, gradle_dist, java_home, jvm_args, gradle_args,
            show_execution_view, show_console_view, override_workspace_settings,
            is_offline, is_build_scans_enabled
        )
        launch_configuration.launch(ILaunchManager.RUN_MODE)
        launch_configuration.delete()

    except Exception as e:
        raise InvocationTargetException(e)

def error(message: str) -> None:
    print(f"Error: {message}")

class GhidraApplicationLayout:
    def __init__(self, ghidra_install_dir_path):
        self.application_installation_dir = os.path.join(ghidra_install_dir_path, "Ghidra")

class JavaConfig:
    def __init__(self, application_installation_dir):
        self.saved_java_home = os.path.join(application_installation_dir, "bin")
