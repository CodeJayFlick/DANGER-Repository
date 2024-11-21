Here's a translation of your Java code into equivalent Python:

```Python
import os
from typing import Dict, List

class GhidraLaunchDelegate:
    def launch(self, configuration: str, mode: str, launch: object, monitor: object) -> None:
        is_headless = configuration.get_type().get_identifier() == "HEADLESS_LAUNCH"
        
        # Get the launch properties associated with the version of Ghidra that is trying to launch
        project_name = configuration.get_attribute("PROJECT_NAME", "")
        java_project = self._get_ghidra_project(project_name)
        if not java_project:
            EclipseMessageUtils.show_error_dialog(f"Failed to launch project '{project_name}'")
            return
        
        ghidra_folder = os.path.join(java_project.get_location(), "GHIDRA_FOLDER_NAME")
        
        try:
            java_config = JavaConfig(ghidra_install_path=ghidra_folder)
        except (ParseException, IOException) as e:
            EclipseMessageUtils.show_error_dialog(f"Failed to launch project '{project_name}'\n{e}")
            return
        
        # Set program arguments
        custom_program_args = configuration.get_attribute("PROGRAM_ARGUMENTS", "").strip()
        if is_headless and not custom_program_args:
            EclipseMessageUtils.show_info_dialog(
                "Ghidra Run Configuration",
                f"Headless launch is being performed without any command line arguments!\n\n"
                f"Edit the '{configuration.name}' run configuration' program arguments to customize headless behavior.  See support/analyzeHeadlessREADME.html for more information."
            )
        
        # Set VM arguments
        vm_args = java_config.get_launch_properties().get_vm_args()
        if is_headless:
            vm_args += f" -Declipse.install.dir={os.path.dirname(os.getcwd())}"
            vm_args += f" -Declipse.workspace.dir={ResourcesPlugin.get_workspace().getRoot().getLocation()}"
            vm_args += f" -Declipse.project.dir={java_project.get_location()}"
        else:
            vm_args = configuration.get_attribute("VM_ARGUMENTS", "").strip()
        
        # Handle special debug mode tasks
        if mode == "debug":
            self._handle_debug_mode()

    def _get_ghidra_project(self, project_name: str) -> object:
        return GhidraProjectUtils.get_ghidra_project(project_name)

    def _handle_debug_mode(self):
        # Switch to debug perspective
        workbench = PlatformUI.get_workbench()
        if workbench is not None:
            perspective_descriptor = workbench.get_perspective_registry().find_perspective_with_id(
                IDebugUIConstants.ID_DEBUG_PERSPECTIVE)
            EclipseMessageUtils.get_workbench_page().set_perspective(perspective_descriptor)

    def _get_project_dependency_dirs(self, java_project: object) -> str:
        paths = ""
        for entry in java_project.get_raw_classpath():
            if entry.get_entry_kind() == IClasspathEntry.CPE_PROJECT:
                resource = ResourcesPlugin.get_workspace().getRoot().find_member(entry.get_path())
                if resource is not None:
                    path = os.path.join(resource.get_location(), "GHIDRA_FOLDER_NAME")
                    paths += f"{os.path.dirname(path)}{File.path_separator}"
        return paths

class JavaConfig:
    def __init__(self, ghidra_install_path: str):
        self.ghidra_install_path = ghidra_install_path
```

This Python code does not include the `EclipseMessageUtils` class or any other classes that were used in your original Java code for displaying error messages and handling perspectives.