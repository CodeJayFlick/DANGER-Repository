class CreateGhidraScriptProjectWizard:
    def __init__(self):
        self.project_page = None
        self.project_config_page = None
        self.ghidra_installation_page = None
        self.python_page = None

    def init(self, wb, selection):
        self.project_page = CreateGhidraProjectWizardPage("GhidraScripts")
        self.project_config_page = ConfigureGhidraScriptProjectWizardPage()
        self.ghidra_installation_page = ChooseGhidraInstallationWizardPage()
        self.python_page = EnablePythonWizardPage(self.ghidra_installation_page)

    def add_pages(self):
        self.add_page(self.project_page)
        self.add_page(self.project_config_page)
        self.add_page(self.ghidra_installation_page)
        self.add_page(self.python_page)

    def perform_finish(self):
        if not self.validate():
            return False

        ghidra_install_dir = self.ghidra_installation_page.get_ghidra_install_dir()
        project_name = self.project_page.get_project_name()
        project_dir = self.project_page.get_project_dir()
        create_run_config = self.project_page.should_create_run_config()
        run_config_memory = self.project_page.get_run_config_memory()
        link_user_scripts = self.project_config_page.should_link_users_scripts()
        link_system_scripts = self.project_config_page.should_link_system_scripts()
        jython_interpreter_name = self.python_page.get_jython_interpreter_name()

        try:
            create(self, ghidra_install_dir, project_name, project_dir,
                   create_run_config, run_config_memory, link_user_scripts,
                   link_system_scripts, jython_interpreter_name)
        except (InterruptedException, InvocationTargetException) as e:
            error("Error occurred during project creation", e)

    def validate(self):
        if self.ghidra_installation_page.get_ghidra_install_dir().contains(self.project_page.get_project_dir()):
            show_error_dialog("Invalid Project Root Directory",
                              "Project root directory cannot reside inside of the selected Ghidra installation directory.")
            return False
        return True

    def create(self, ghidra_install_dir, project_name, project_dir,
               create_run_config, run_config_memory, link_user_scripts,
               link_system_scripts, jython_interpreter_name):
        try:
            info("Creating " + project_name + " at " + project_dir)
            begin_task("Creating " + project_name, 2)

            ghidra_layout = GhidraApplicationLayout(ghidra_install_dir)
            worked(1)

            create_ghidra_script_project(project_name, project_dir,
                                         create_run_config, run_config_memory,
                                         link_user_scripts, link_system_scripts,
                                         ghidra_layout, jython_interpreter_name)

            info("Finished creating " + project_name)
        except (IOException, ParseException, CoreException) as e:
            raise InvocationTargetException(e)
        finally:
            done()

def create_ghidra_script_project(project_name, project_dir, create_run_config,
                                 run_config_memory, link_user_scripts,
                                 link_system_scripts, ghidra_layout,
                                 jython_interpreter_name):
    # Your code here
