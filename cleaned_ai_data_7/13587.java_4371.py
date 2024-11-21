import os
from typing import Set

class ModuleTemplateType:
    ANALYZER = ("Analyzer", "Extends Ghidra analysis")
    PLUGIN = ("Plugin", "Extends the Ghidra user interface")
    LOADER = ("Loader", "Loads/imports a binary file format into Ghidra")
    FILESYSTEM = ("FileSystem", "Opens a file system format for browsing or batch import")
    EXPORTER = ("Exporter", "Exports/ saves a Ghidra program to a specific file format")
    PROCESSOR = ("Processor", "Enables disassembly/decompilation of a processor/architecture")

class GhidraModuleUtils:
    @staticmethod
    def create_ghidra_module_project(project_name: str, project_dir: str, 
                                     create_run_config: bool, run_config_memory: str, 
                                     ghidra_layout: dict, jython_interpreter_name: str, 
                                     monitor) -> None:
        # Create empty Ghidra project
        java_project = {}
        project = {"project": java_project}
        
        # Create source directories
        source_folders = []
        for folder in ["src/main/java", "src/main/help", "src/main/resources"]:
            os.makedirs(os.path.join(project_dir, folder), exist_ok=True)
            source_folders.append(folder)

        # Put the source directories in the project's classpath
        classpath_entries = []
        for source_folder in source_folders:
            classpath_entries.append({"source_entry": {"folder_path": source_folder}})

    @staticmethod
    def configure_module_source(java_project: dict, project_dir: str, 
                                 ghidra_layout: dict, module_template_types: Set[ModuleTemplateType], 
                                 monitor) -> None:
        skeleton_pkg = "skeleton"
        skeleton_class = "Skeleton"

        # Create a list of files to exclude
        exclude_regexes = []
        for template_type in ModuleTemplateType.__dict__.values():
            if not module_template_types.contains(template_type):
                if template_type == ModuleTemplateType.PROCESSOR:
                    exclude_regexes.append("languages")
                    exclude_regexes.append("buildLanguage.xml")
                    exclude_regexes.append("sleighArgs.txt")
                else:
                    exclude_regexes.append(f"{skeleton_class}{template_type.name}.java")

        # Copy the skeleton files
        ghidra_install_dir = ghidra_layout["application_installation_dir"]
        skeleton_dir = os.path.join(ghidra_install_dir, "Skeleton")
        
        try:
            FileUtilities.copy_dir(skeleton_dir, project_dir, lambda f: not any(map(lambda r: re.compile(r).match(f.name), exclude_regexes)))
        except (CancelledException, IOException) as e:
            print("Failed to copy skeleton directory:", project_dir)

    @staticmethod
    def write_ant_properties(project: dict, ghidra_layout: dict) -> None:
        if not GhidraProjectUtils.is_ghidra_module_project(project):
            return

        data_folder = {"folder": "data"}
        
        try:
            with open(os.path.join(project_dir, ".antProperties.xml"), 'w') as f:
                writer = PrintWriter(f)
                writer.println("# This file is generated on each \"Link Ghidra\" command. Do not modify.")
                writer.println()
                writer.println("<project>")
                writer.println("   <property name=\"ghidra.install.dir\" value=\"" + ghidra_install_dir + "\" />")
                writer.println("</project>")
        except Exception as e:
            print("Failed to write ant properties file:", project_dir)

    @staticmethod
    def rename_java_element(element: dict, new_name: str, monitor) -> None:
        if element["element_type"] == "package_fragment":
            id = IJavaRefactorings.RENAME_PACKAGE
        elif element["element_type"] == "compilation_unit":
            id = IJavaRefactorings.RENAME_COMPILATION_UNIT
        else:
            raise ValueError("Can only rename packages and compilation units!")

    @staticmethod
    def is_ghidra_module_project(project: dict) -> bool:
        return True

GhidraModuleUtils.create_ghidra_module_project("project_name", "project_dir", 
                                               create_run_config=True, run_config_memory="run_config_memory", 
                                               ghidra_layout={"ghidra_installation_dir": "/path/to/ghidra"}, 
                                               jython_interpreter_name="jython_interpreter_name")
GhidraModuleUtils.configure_module_source({"java_project": "project"}, "project_dir", 
                                          {"ghidra_layout": "/path/to/ghidra"}, set([ModuleTemplateType.ANALYZER, ModuleTemplateType.PLUGIN]), None)
GhidraModuleUtils.write_ant_properties({"project": "project"}, {"ghidra_layout": "/path/to/ghidra"})
