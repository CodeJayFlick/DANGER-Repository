class ApplicationModule:
    def __init__(self, application_root, module_dir):
        self.application_root = application_root
        self.module_dir = module_dir
        file_path = str(module_dir)
        root_path = str(application_root)
        if not file_path.startswith(root_path):
            raise AssertionError("ApplicationRoot is not in the parent path of moduleDir!")
        
        relative_path = file_path[len(root_path) + 1:]
    
    def get_name(self):
        return self.module_dir.name
    
    def get_module_dir(self):
        return self.module_dir

    def get_application_root(self):
        return self.application_root

    def get_relative_path(self):
        return self.relative_path

    def is_extension(self):
        parent = self.module_dir.parent
        if parent:
            return str(parent).lower() == "extensions"
    
    def is_framework(self):
        parent = self.module_dir.parent
        if parent:
            return str(parent).lower() == "framework"

    def is_debug(self):
        parent = self.module_dir.parent
        if parent:
            return str(parent).lower() == "debug"

    def is_processor(self):
        parent = self.module_dir.parent
        if parent:
            return str(parent).lower() == "processors"

    def is_feature(self):
        parent = self.module_dir.parent
        if parent:
            return str(parent).lower() == "features"

    def is_configuration(self):
        parent = self.module_dir.parent
        if parent:
            return str(parent).lower() == "configurations"

    def is_gpl(self):
        parent = self.module_dir.parent
        if parent:
            return str(parent).lower() == "gpl"
    
    def __lt__(self, other):
        my_rank = self.get_rank()
        other_rank = other.get_rank()
        result = my_rank - other_rank
        if result == 0:
            result = self.get_name().casefold().__lt__(other.get_name().casefold())
        return result
    
    def __str__(self):
        return str(self.module_dir.name)

    def get_rank(self):
        name = self.get_name()
        if name.lower() == "renoirgraph":
            return 10
        elif self.is_framework():
            return 1
        elif self.is_feature():
            return 2
        elif self.is_processor():
            return 3
        else:
            return 4
    
    def exclude_from_ghidra_jar(self):
        try:
            application_roots = Application.get_application_root_directories()
            
            root_dir_parents = set()
            for root in application_roots:
                root_dir_parents.add(root.parent)
            
            module_manifest_file = ModuleManifestFile(self.module_dir)
            return module_manifest_file.exclude_from_ghidra_jar()
        except Exception as e:
            return False
