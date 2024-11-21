import os
from typing import List

class HeadlessGhidraApplicationConfiguration:
    def __init__(self):
        pass

    def initialize_application(self) -> None:
        super().initialize_application()

        # Now that preferences are accessible, finalize classpath by adding user plugin paths.
        self.add_user_jar_and_plugin_paths_to_classpath()
        
        monitor.set_message("Performing class searching...")
        self.perform_class_searching()

        # Locate certs if found (must be done before module initialization)
        self.locate_cacerts_file()

        monitor.set_message("Performing module initialization...")
        self.perform_module_initialization()

    def add_user_jar_and_plugin_paths_to_classpath(self) -> None:
        if Application.in_single_jar_mode():
            return

        ghidra_loader = GhidraClassLoader()
        for path in Preferences.get_plugin_paths():
            ghidra_loader.add_path(path)

    def perform_class_searching(self) -> None:
        try:
            ClassSearcher.search(monitor)
        except CancelledException as e:
            print(f"Class searching unexpectedly cancelled: {e}")

    def locate_cacerts_file(self) -> None:
        for app_root in Application.get_application_root_directories():
            cacerts_file = os.path.join(app_root, "cacerts")
            if os.path.isfile(cacerts_file):
                os.environ[ApplicationTrustManagerFactory.GHIDRA_CACERTS_PATH_PROPERTY] = cacerts_file
                break

    def perform_module_initialization(self) -> None:
        instances: List[ModuleInitializer] = ClassSearcher.get_instances(ModuleInitializer)
        for initializer in instances:
            monitor.set_message(f"Initializing {initializer.name}...")
            initializer.run()

class GhidraClassLoader:
    pass

class Preferences:
    @staticmethod
    def get_plugin_paths() -> list:
        return []

class Application:
    @staticmethod
    def in_single_jar_mode() -> bool:
        return False

    @staticmethod
    def get_application_root_directories() -> list:
        return []
