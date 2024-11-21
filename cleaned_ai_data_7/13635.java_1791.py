class MacJavaFinder:
    def __init__(self):
        pass

    def get_java_root_install_dirs(self):
        java_root_install_dirs = []
        java_root_install_dirs.append('/Library/Java/JavaVirtualMachines')
        return java_root_install_dirs

    def get_java_home_sub_dir_path(self):
        return 'Contents/Home'
