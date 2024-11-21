class HeadlessOptions:
    def __init__(self):
        self.reset()

    def reset(self):
        self.domain_filename_to_process = None
        self.run_scripts_no_import = False
        self.pre_scripts = []
        self.post_scripts = []
        self.script_paths = None
        self.properties_file_str_paths = []
        self.properties_file_paths = []
        self.overwrite = False
        self.recursive = False
        self.read_only = False
        self.delete_project = False
        self.analyze = True
        self.language = None
        self.compiler_spec = None
        self.per_file_timeout = -1
        self.keystore = None
        self.connect_user_id = None
        self.allow_password_prompt = False
        self.commit = False
        self.commit_comment = None
        self.ok_to_delete = False
        self.maxcpu = 0

    def set_run_scripts_no_import(self, run_scripts_only: bool, filename: str):
        if filename is not None:
            filename = filename.strip()
            if '/' in filename:
                raise ValueError("Invalid filename specified")
        self.run_scripts_no_import = run_scripts_only
        self.domain_filename_to_process = filename

    def set_pre_scripts(self, pre_scripts: list):
        empty_args = []
        for script in pre_scripts:
            empty_args.append((script, []))
        self.set_pre_scriptsWithArgs(empty_args)

    def set_pre_scriptsWithArgs(self, scripts_with_args: list):
        self.pre_scripts = scripts_with_args
        self.pre_script_file_map = None

    def set_post_scripts(self, post_scripts: list):
        empty_args = []
        for script in post_scripts:
            empty_args.append((script, []))
        self.set_post_scriptsWithArgs(empty_args)

    def set_post_scriptsWithArgs(self, scripts_with_args: list):
        self.post_scripts = scripts_with_args
        self.post_script_file_map = None

    def set_script_directories(self, new_paths: list):
        self.script_paths = new_paths

    def set_properties_file_directory(self, path: str):
        self.properties_file_str_paths.append(path)

    def set_properties_file_directories(self, paths: list):
        self.properties_file_str_paths = paths

    def enable_overwrite_on_conflict(self, enabled: bool):
        self.overwrite = enabled

    def enable_recursive_processing(self, enabled: bool):
        self.recursive = enabled

    def enable_read_only_processing(self, enabled: bool):
        self.read_only = enabled

    def set_delete_created_project_on_close(self, enabled: bool):
        self.delete_project = enabled

    def enable_analysis(self, enabled: bool):
        self.analyze = enabled

    def set_language_and_compiler(self, language_id: str, compiler_spec_id: str) -> None:
        if language_id is not None and compiler_spec_id is not None:
            try:
                from ghidra.program.model.lang import LanguageID
                from ghidra.util.exception import InvalidInputException
                self.language = DefaultLanguageService.get_language(LanguageID(language_id))
                if compiler_spec_id is not None:
                    self.compiler_spec = self.language.get_compiler_spec_by_id(CompilerSpecID(compiler_spec_id))
            except (InvalidInputException, LanguageNotFoundException):
                raise

    def set_per_file_analysis_timeout(self, timeout: str) -> None:
        try:
            self.per_file_timeout = int(timeout)
        except ValueError as e:
            raise InvalidInputException(str(e))

    def set_client_credentials(self, user_id: str, keystore_path: str, allow_password_prompt: bool) -> None:
        if user_id is not None and keystore_path is not None:
            self.connect_user_id = user_id
            self.keystore = keystore_path
            from ghidra.framework.client import HeadlessClientAuthenticator
            try:
                HeadlessClientAuthenticator.install_headless_client_authenticator(user_id, keystore_path, allow_password_prompt)
            except Exception as e:
                raise

    def set_commit_files(self, commit: bool, comment: str) -> None:
        self.commit = commit
        if comment is not None and commit:
            self.commit_comment = comment

    def set_ok_to_delete(self, delete_ok: bool) -> None:
        self.ok_to_delete = delete_ok

    def set_max_cpu(self, cpu: int):
        self.maxcpu = cpu
