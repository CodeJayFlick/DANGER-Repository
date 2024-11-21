class WindowsJavaFinder:
    def get_java_root_install_dirs(self):
        return [f"C:\\Program Files\\Java", f"C:\\Program Files\\Amazon Corretto"]

    def get_java_home_sub_dir_path(self):
        return ""

    def get_jre_home_from_java_home(self, java_home_dir):
        if java_home_dir.name.startswith("jdk"):
            return Path(java_home_dir.parent) / (java_home_dir.name.replace("jdk", "jre"))
        else:
            return java_home_dir

    def get_jdk_home_from_java_home(self, java_home_dir):
        if java_home_dir.name.startswith("jre"):
            return Path(java_home_dir.parent) / (java_home_dir.name.replace("jre", "jdk"))
        else:
            return java_home_dir
