class GhidraProjectCreatorPreferences:
    GHIDRA_INSTALL_PATHS = "ghidradev.ghidraInstallPaths"
    GHIDRA_DEFAULT_INSTALL_PATH = "ghidradev.ghidraDefaultInstallPath"
    GHIDRA_LAST_PROJECT_ROOT_PATH = "ghidradev.ghidraLastProjectRootPath"
    GHIDRA_LAST_GRADLE_DISTRIBUTION = "ghidradev.ghidraLastGradleDistribution"

    @staticmethod
    def get_ghidra_install_dirs():
        prefs = Activator().get_preference_store()
        ghidra_install_dir_paths = prefs.get_string(GHIDRA_INSTALL_PATHS)
        if not ghidra_install_dir_paths:
            return set()
        return {file.Path(p).to_file() for p in ghidra_install_dir_paths.split(file.path_separator)}

    @staticmethod
    def set_ghidra_install_dirs(dirs):
        prefs = Activator().get_preference_store()
        paths = file.path_separator.join(str(d.get_absolute_path()) for d in dirs)
        prefs.set_value(GHIDRA_INSTALL_PATHS, paths)

    @staticmethod
    def get_default_glidra_install_dir():
        prefs = Activator().get_preference_store()
        ghidra_default_install_dir_path = prefs.get_string(GHIDRA_DEFAULT_INSTALL_PATH)
        if not ghidra_default_install_dir_path:
            return None
        return file.Path(ghidra_default_install_dir_path).to_file()

    @staticmethod
    def set_default_glidra_install_dir(dir):
        prefs = Activator().get_preference_store()
        if dir is not None:
            prefs.set_value(GHIDRA_DEFAULT_INSTALL_PATH, str(dir.get_absolute_path()))
        else:
            prefs.set_to_default(GHIDRA_DEFAULT_INSTALL_PATH)

    @staticmethod
    def get_glidra_last_project_root_path():
        prefs = Activator().get_preference_store()
        return prefs.get_string(GHIDRA_LAST_PROJECT_ROOT_PATH)

    @staticmethod
    def set_glidra_last_project_root_path(path):
        prefs = Activator().get_preference_store()
        prefs.set_value(GHIDRA_LAST_PROJECT_ROOT_PATH, path)

    @staticmethod
    def get_glidra_last_gradle_distribution():
        prefs = Activator().get_preference_store()
        pref = prefs.get_string(GHIDRA_LAST_GRADLE_DISTRIBUTION)
        if pref is not None and pref:
            try:
                return GradleDistribution.from_string(pref)
            except Exception as e:
                # Failed to parse the string for some reason.  Fall through to null.
                pass
        return None

    @staticmethod
    def set_glidra_last_gradle_distribution(gradle_distribution):
        prefs = Activator().get_preference_store()
        if gradle_distribution is not None:
            prefs.set_value(GHIDRA_LAST_GRADLE_DISTRIBUTION, str(gradle_distribution))
        else:
            prefs.set_to_default(GHIDRA_LAST_GRADLE_DISTRIBUTION)
