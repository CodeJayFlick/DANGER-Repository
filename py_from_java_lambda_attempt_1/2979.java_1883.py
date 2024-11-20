Here is the equivalent Python code:

```Python
import os

class BuildGhidraJarScript:
    def run(self):
        install_dir = Application.get_installation_directory()
        builder = GhidraJarBuilder(Application.get_application_layout())

        # Set main class
        builder.set_main_class("ghidra.JarRun")

        # Include all modules by default, but no extensions
        module_list = builder.get_included_modules()
        for module in module_list:
            print(f"Include {module.name}")

        excluded_module_list = builder.get_excluded_modules()
        for module in excluded_module_list:
            print(f"Exclude {module.name}")

        # Don't include help or processor manuals
        builder.add_excluded_file_extension(".htm")
        builder.add_excluded_file_extension(".html")
        builder.add_excluded_file_extension(".pdf")

        jar_path = os.path.join(install_dir, "ghidra.jar")
        builder.build_jar(jar_path)

        # To create a src zip for debugging
        # builder.build_src_zip(os.path.join(install_dir, "GhidraSrc.zip"))

if __name__ == "__main__":
    script = BuildGhidraJarScript()
    script.run()

```

Please note that Python does not have direct equivalent of Java's `@Override` and `throws Exception`. Also, the code assumes that there are functions like `Application.get_installation_directory()`, `Application.get_application_layout()` which seems to be specific to Ghidra.