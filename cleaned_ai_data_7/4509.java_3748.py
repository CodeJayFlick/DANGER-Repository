import os
import collections

class GhidraScriptUtil:
    USER_SCRIPTS_DIR = None  # will be set later
    SCRIPTS_SUBDIR_NAME = "ghidra_scripts"
    DEV_SCRIPTS_SUBDIR_NAME = "developer_scripts"

    providers = None
    reference_count = AtomicInteger(0)

    @staticmethod
    def get_bundle_host():
        return bundle_host

    @staticmethod
    def set_bundle_host(aBundleHost):
        if bundle_host is not None:
            raise RuntimeError("GhidraScriptUtil initialized multiple times!")
        try:
            global bundle_host
            bundle_host = aBundleHost
            bundle_host.start_framework()
        except (OSGiException, IOException) as e:
            print(f"Failed to initialize BundleHost: {e}")

    @staticmethod
    def initialize(aBundleHost, extra_system_paths):
        set_bundle_host(aBundleHost)
        if extra_system_paths is not None:
            for path in extra_system_paths:
                bundle_host.add(ResourceFile(path), True, True)

        bundle_host.add(get_user_script_directory(), True, False)
        system_script_directories = get_system_script_directories()
        bundle_host.add(system_script_directories[0], True, True)

    @staticmethod
    def dispose():
        if bundle_host is not None:
            bundle_host.dispose()
            global bundle_host
            bundle_host = None

        global providers
        providers = None

    @staticmethod
    def get_script_source_directories():
        return [file for file in os.listdir(bundle_host.get_bundle_files()) if os.path.isdir(os.path.join(bundle_host.get_bundle_files(), file))]

    @staticmethod
    def find_source_directory_containing(source_file):
        for source_dir in GhidraScriptUtil.get_script_source_directories():
            rel_path = os.path.relpath(source_file, source_dir)
            if rel_path is not None:
                return ResourceFile(os.path.join(bundle_host.get_bundle_files(), source_dir), rel_path)

    @staticmethod
    def find_script_by_name(script_name):
        for file in GhidraScriptUtil.get_script_source_directories():
            if os.path.basename(file) == script_name:
                return file

    @staticmethod
    def build_user_scripts_directory():
        root = os.environ["USER_HOME"]
        override = os.environ.get("GHIDRA_SCRIPTS_DIR")
        if override is not None:
            print(f"Using Ghidra script source directory: {root}")
            root = override

        return f"{root}/{GhidraScriptUtil.SCRIPTS_SUBDIR_NAME}"

    @staticmethod
    def get_system_script_directories():
        system_script_dirs = []
        add_script_directories(system_script_dirs, GhidraScriptUtil.SCRIPTS_SUBDIR_NAME)
        add_script_directories(system_script_dirs, GhidraScriptUtil.DEV_SCRIPTS_SUBDIR_NAME)

        return sorted(system_script_dirs)

    @staticmethod
    def get_user_script_directory():
        return ResourceFile(GhidraScriptUtil.build_user_scripts_directory())

    @staticmethod
    def is_system_script(file):
        try:
            file_path = os.path.relpath(file, GhidraScriptUtil.USER_SCRIPTS_DIR)
            if file_path.startswith("/"):
                # a script inside of the user scripts dir is not a 'system' script
                return False

            for root in Application.get_application_root_directories():
                install_path = os.path.relpath(root, "/")
                if file_path.startswith(install_path):
                    return True

        except (IOError) as e:
            print(f"Failed to find file in system directories: {file}")

        return False

    @staticmethod
    def get_exploded_compiled_source_bundle_paths():
        try:
            return [os.path.join(root, name) for root, dirs, files in os.walk(Application.get_osgi_dir()) if "exploded-compiled-source" in dirs]

        except (IOError) as e:
            print(f"error listing user osgi directory: {e}")
            return []

    @staticmethod
    def get_base_name(script):
        name = script.name
        pos = name.rfind(".")
        if pos == -1:
            return name

        return name[:pos]

    @staticmethod
    def get_providers():
        if GhidraScriptUtil.providers is None:
            providers = [GhidraScriptProvider.get_instances(GhidraScriptProvider)]
            sorted(providers)
            GhidraScriptUtil.providers = providers

        return providers

    @staticmethod
    def create_new_script(provider, parent_directory, script_directories):
        base_name = "default"
        extension = provider.extension
        try:
            file_path = os.path.join(parent_directory, f"{base_name}{extension}")
            if not os.path.exists(file_path):
                with open(file_path, "w") as f:
                    pass

            return ResourceFile(os.path.dirname(file_path), os.path.basename(file_path))

        except (IOError) as e:
            print(f"Unable to create new script file: {e}")

    @staticmethod
    def find_provider(script_file):
        for provider in GhidraScriptUtil.get_providers():
            if script_file.endswith(provider.extension.lower()):
                return provider

        return None

    @staticmethod
    def has_script_provider(script_file):
        return GhidraScriptUtil.find_provider(script_file) is not None

    @staticmethod
    def new_script_info(file):
        return ScriptInfo(GhidraScriptUtil.get_provider(file), file)

    @staticmethod
    def fixup_name(name):
        provider = GhidraScriptUtil.find_provider(name)
        if provider is None:
            name += ".java"
            provider = GhidraScriptUtil.find_provider(".java")

        return provider.fixup_name(name)

    @staticmethod
    def find_script_file_in_paths(script_directories, name):
        validated_name = GhidraScriptUtil.fixup_name(name)
        for file in script_directories:
            if os.path.isdir(file):
                path = os.path.join(file, validated_name)
                if os.path.exists(path):
                    return ResourceFile(os.path.dirname(path), os.path.basename(path))

    @staticmethod
    def acquire_bundle_host_reference():
        if GhidraScriptUtil.reference_count.get_and_increment() == 0:
            initialize(bundle_host, None)

        return bundle_host

    @staticmethod
    def release_bundle_host_reference():
        if GhidraScriptUtil.reference_count.get_and_decrement() == 1:
            dispose()

class ResourceFile:
    def __init__(self, parent_directory, name):
        self.parent_directory = parent_directory
        self.name = name

    def get_path(self):
        return os.path.join(self.parent_directory, self.name)

    @staticmethod
    def is_directory(file):
        return os.path.isdir(file.get_path())

class ScriptInfo:
    def __init__(self, provider, file):
        self.provider = provider
        self.file = file

# Initialize the bundle host and providers
bundle_host = None
GhidraScriptUtil.providers = []
