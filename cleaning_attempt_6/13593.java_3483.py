class CreateGhidraModuleProjectWizard:
    def __init__(self):
        self.workbench = None
        self.project_page = None
        self.project_config_page = None
        self.ghidra_installation_page = None
        self.python_page = None

    def init(self, workbench: object, selection: list) -> None:
        self.workbench = workbench
        self.project_page = CreateGhidraProjectWizardPage()
        self.project_config_page = ConfigureGhidraModuleProjectWizardPage()
        self.ghidra_installation_page = ChooseGhidraInstallationWizardPage()
        self.python_page = EnablePythonWizardPage(self.ghidra_installation_page)

    def add_pages(self) -> None:
        self.add_page(self.project_page)
        self.add_page(self.project_config_page)
        self.add_page(self.ghidra_installation_page)
        self.add_page(self.python_page)

    def perform_finish(self) -> bool:
        if not self.validate():
            return False

        ghidra_install_dir = self.ghidra_installation_page.get_ghidra_install_dir()
        project_name = self.project_page.get_project_name()
        create_run_config = self.project_page.should_create_run_config()
        run_config_memory = self.project_page.get_run_config_memory()
        project_dir = self.project_page.get_project_dir()
        jython_interpreter_name = self.python_page.get_jython_interpreter_name()
        module_template_types = self.project_config_page.get_module_template_types()

        try:
            container = get_container()
            monitor = create(monitor=True, false=False)
            run(container, True, False, ghidra_install_dir, project_name, project_dir,
                create_run_config, run_config_memory, module_template_types, jython_interpreter_name, monitor)

        except (InterruptedException, InvocationTargetException) as e:
            error(show_wizard_error_dialog(get_shell(), e), e)
            return False

        return True

    def create(self, ghidra_install_dir: str, project_name: str, project_dir: str,
               create_run_config: bool, run_config_memory: str, module_template_types: list,
               jython_interpreter_name: str, monitor) -> None:
        try:
            info("Creating " + project_name + " at " + project_dir)
            monitor.begin_task("Creating " + project_name, 3)

            ghidra_layout = GhidraApplicationLayout(ghidra_install_dir)
            monitor.worked(1)

            java_project = create_ghidra_module_project(project_name, project_dir,
                create_run_config, run_config_memory, ghidra_layout, jython_interpreter_name, monitor)
            monitor.worked(1)

            source_file = configure_module_source(java_project, project_dir, ghidra_layout,
                module_template_types, monitor)
            monitor.worked(1)

            if source_file is not None:
                display_in_editor(source_file, workbench)

        except (IOException, ParseException, CoreException) as e:
            raise InvocationTargetException(e)

        finally:
            monitor.done()

    def validate(self) -> bool:
        if self.ghidra_installation_page.get_ghidra_install_dir().contains(
            self.project_page.get_project_dir()):
            show_error_dialog("Invalid Project Root Directory",
                "Project root directory cannot reside inside of the selected Ghidra installation directory.")
            return False
        return True

class CreateGhidraProjectWizardPage:
    def get_project_name(self) -> str:
        pass  # Implement this method in your subclass.

    def should_create_run_config(self) -> bool:
        pass  # Implement this method in your subclass.

    def get_run_config_memory(self) -> str:
        pass  # Implement this method in your subclass.

    def get_project_dir(self) -> str:
        pass  # Implement this method in your subclass.
