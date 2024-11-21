import os
from collections import OrderedDict, defaultdict

class GhidraLauncher:
    def __init__(self):
        pass

    @staticmethod
    def launch(args):
        try:
            layout = GhidraApplicationLayout()
            cls = ClassLoader.get_system_classloader().load_class(args[0])
            if not issubclass(cls, GhidraLaunchable):
                raise Exception(f"\"{args[0]}\" is not a launchable class")
            launchable = cls.__new__(cls)
            launchable.launch(layout, args[1:])
        except Exception as e:
            print(str(e))

    @staticmethod
    def main(args):
        GhidraLauncher.launch(args)

class GhidraApplicationLayout:
    pass

def initialize_ghidra_environment():
    if not isinstance(ClassLoader.get_system_classloader(), GhidraClassLoader):
        raise ClassNotFoundException("Ghidra class loader not in use. Confirm JVM argument '-Djava.system.class.loader' is set.")
    loader = ClassLoader.get_system_classloader()
    layout = GhidraApplicationLayout()
    classpath_list = build_classpath(layout)
    for path in classpath_list:
        loader.add_path(path)
    return layout

def build_classpath(layout):
    classpath_list = []
    modules = get_ordered_modules(layout)
    if SystemUtilities.is_in_development_mode():
        add_module_bin_paths(classpath_list, modules)
        add_external_jar_paths(classpath_list, layout.get_application_root_dirs())
    else:
        add_patch_paths(classpath_list, layout.get_patch_dir())
        add_module_jar_paths(classpath_list, modules)
    classpath_list = order_classpath(classpath_list, modules)
    return classpath_list

def add_patch_paths(path_list, patch_dir):
    if not os.path.exists(patch_dir) or not os.path.isdir(patch_dir):
        return
    path_list.append(os.path.abspath(patch_dir))
    jars = find_jars_in_dir(patch_dir)
    for jar in jars:
        path_list.append(jar)

def add_module_bin_paths(path_list, modules):
    dirs = ModuleUtilities.get_module_bin_directories(modules)
    for dir in dirs:
        if os.path.exists(dir) and os.path.isdir(dir):
            path_list.append(os.path.abspath(dir))

def add_module_jar_paths(path_list, modules):
    dirs = ModuleUtilities.get_module_lib_directories(modules)
    for dir in dirs:
        jars = find_jars_in_dir(dir)
        for jar in jars:
            if not jar in path_list:
                path_list.append(jar)

def add_external_jar_paths(path_list, app_root_dirs):
    libdeps_file = None
    for root in app_root_dirs:
        file_path = os.path.join(root, "build", "libraryDependencies.txt")
        if os.path.exists(file_path) and os.path.isfile(file_path):
            libdeps_file = file_path
            break
    if not libdeps_file or not os.path.exists(libdeps_file) or not os.path.isfile(libdeps_file):
        raise FileNotFoundError("Files listed in 'build/libraryDependencies.txt' are incorrect--rebuild this file")
    path_set = set()
    with open(libdeps_file, "r") as reader:
        for line in reader.readlines():
            if line.strip().endswith(".jar"):
                jar_path = os.path.join(root, line.strip())
                if not os.path.exists(jar_path) or not os.path.isfile(jar_path):
                    print(f"Failed to find required jar file: {jar_path}")
                    continue
                path_set.add(os.path.abspath(jar_path))
    for path in sorted(path_set):
        if not path in path_list:
            path_list.append(path)

def find_jars_in_dir(dir):
    jars = []
    dir_names = os.listdir(dir)
    for name in dir_names:
        file_path = os.path.join(dir, name)
        if os.path.isfile(file_path) and name.endswith(".jar"):
            jars.append(os.path.abspath(file_path))
    return sorted(jars)

def get_ordered_modules(layout):
    comparator = lambda module1, module2: (module1.name().lower(), module2.name().lower())
    modules = OrderedDict()
    for module in layout.get_modules().values():
        if ModuleUtilities.is_external_module(module, layout):
            continue
        type_priority_map = {"framework": 0, "configurations": 1, "features": 2, "debug": 3, "processors": 4, "gpl": 5, "extensions": 6, "test": 7}
        module_type = os.path.dirname(module.get_module_root().getAbsolutePath()).lower()
        priority = type_priority_map.get(module_type.lower(), len(type_priority_map))
        modules[module.name()] = (priority, module)
    sorted_modules = sorted(modules.values())
    for _, module in sorted_modules:
        modules[module.name()] = module
    return OrderedDict((name, module) for name, module in modules.items())

def order_classpath(path_list, modules):
    fat_jars = set()
    for module in modules.values():
        for jar in module.get_fat_jars():
            if os.path.basename(jar).lower() not in path_list:
                continue
            fat_jars.add(os.path.abspath(jar))
    ordered_path_list = [path for path in path_list]
    for path in path_list[:]:
        if path.lower() in fat_jars:
            ordered_path_list.remove(path)
            ordered_path_list.append(path)
    return ordered_path_list

if __name__ == "__main__":
    GhidraLauncher.main(sys.argv[1:])
