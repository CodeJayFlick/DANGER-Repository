class GFileSystemLoadKernelTask:
    def __init__(self, plugin, program_manager, file_list):
        self.file_list = file_list
        self.program_manager = program_manager
        super().__init__("Loading iOS kernel...", True, True, True)

    def run(self, monitor):
        if not self.file_list:
            print("Nothing to do")
            return

        if len(set([fsrl.get_container().get_name() for fsrl in self.file_list])) > 1:
            print("The list of files to import must be from the same filesystem")
            return

        first_file = self.file_list[0]
        try:
            file_system = FileSystemService.getInstance().get_refd_file(first_file, monitor).fs_ref.get_filesystem()
            container_name = file_system.get_fsrl().get_container().get_name()
            monitor.set_message("Loading iOS Kernel from " + container_name + "...")

            for fsrl in self.file_list:
                if monitor.is_cancelled():
                    break
                gfile = first_file.fs_ref.get_filesystem().lookup(fsrl.get_path())
                self.process(gfile, monitor)

        except (UnsupportedOperationException, IOException, CancelledException) as e:
            print("Error extracting file: " + str(e))

    def process(self, gfile, monitor):
        if self.is_special_directory(gfile):
            return

        if gfile.is_directory() and not ((gfilesystemprogramprovider)(gfile.get_filesystem())).can_provide_program(gfile):
            listing = gfile.get_filesystem().get_listing(gfile)
            for child in listing:
                if monitor.is_cancelled():
                    break
                self.process(child, monitor)

        else:
            try:
                self.load_kext(gfile, monitor)

            except Exception as e:
                print("unable to load kext file: " + gfile.get_name(), str(e))

    def is_special_directory(self, directory):
        return False

    def load_kext(self, gfile, monitor):
        if not gfile.get_length():
            return
        if not gfile.get_name().endswith(".kext"):
            return
        monitor.set_message("Opening " + gfile.get_name())

        program = ProgramMappingService.find_matching_program_open_if_needed(gfile.get_fsrl(), self, self.program_manager, 0)
        if program:
            program.release(self)
            return

        # file_cache_file = FileSystemService.getInstance().get_file(gfile.get_fsrl(), monitor)

        if isinstance(gfile.get_filesystem(), GFileSystemProgramProvider):
            language_service = DefaultLanguageService.get_language_service()
            gfilesystemprogramprovider = (gfilesystemprogramprovider)(gfile.get_filesystem())
            program = gfilesystemprogramprovider.get_program(gfile, language_service, monitor, self)
        else:
            return

        if program:
            try:
                domain_folder = ProjectDataUtils.create_domain_folder_path(AppInfo.getActive_project().get_project_data().get_root_folder(), gfile.get_parent_file().get_path())
                file_name = ProjectDataUtils.get_unique_name(domain_folder, program.get_name())

                GhidraProgramUtilities.set_analyzed_flag(program, True)
                ImporterUtilities.set_program_properties(program, gfile.get_fsrl(), monitor)

                domain_folder.create_file(file_name, program, monitor)

                self.program_manager.open_program(program)
                ProgramMappingService.create_association(gfile.get_fsrl(), program)

            finally:
                program.release(self)
