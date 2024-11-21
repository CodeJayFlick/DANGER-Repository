class ApplyDataArchiveAnalyzer:
    NAME = "Apply Data Archives"
    DESCRIPTION = "Apply known data type archives based on program information."
    
    OPTION_NAME_CREATE_BOOKMARKS = "Create Analysis Bookmarks"
    OPTION_DESCRIPTION_CREATE_BOOKMARKS = f"If checked, an analysis bookmark will be created at each symbol address {''}where multiple function definitions were found and not applied."
    OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED = True
    create_bookmarks_enabled = OPTION_DEFAULT_CREATE_BOOKMARKS_ENABLED

    def __init__(self):
        super().__init__(NAME, DESCRIPTION)
        self.set_priority(AnalysisPriority.FUNCTION_ID_ANALYSIS.after())
        self.default_enablement(True)

    def added(self, program: 'Program', address_set_view: 'AddressSetView', task_monitor: 'TaskMonitor', message_log: 'MessageLog'):
        auto_analysis_manager = AutoAnalysisManager.get_analysis_manager(program)
        data_type_manager_service = auto_analysis_manager.data_type_manager_service

        archive_list = DataTypeArchiveUtility.get_archive_list(program)
        manager_list = []
        task_monitor.initialize(len(archive_list))

        for archive_name in archive_list:
            if task_monitor.is_cancelled():
                break
            dtm = None
            try:
                dtm = data_type_manager_service.open_data_type_archive(archive_name)
                if dtm is None:
                    message_log.append_msg("Apply Data Archives", f"Failed to locate data type archive: {archive_name}")
                else:
                    manager_list.append(dtm)
            except Exception as e:
                cause = e.__cause__
                if isinstance(cause, VersionException):
                    message_log.append_msg("Apply Data Archives", f"Unable to open archive {archive_name}: {cause}")
                else:
                    msg = str(e) if not hasattr(e, 'message') else e.message
                    message_log.append_msg("Apply Data Archives", f"Unexpected Error opening archive {archive_name}: {msg}")

        task_monitor.set_message("Applying Function Signatures...")
        cmd = ApplyFunctionDataTypesCmd(manager_list, address_set_view, SourceType.IMPORTED, False, self.create_bookmarks_enabled)
        cmd.apply_to(program, task_monitor)

    def register_options(self, options: 'Options', program: 'Program'):
        options.register_option(self.OPTION_NAME_CREATE_BOOKMARKS, self.create_bookmarks_enabled, None, self.OPTION_DESCRIPTION_CREATE_BOOKMARKS)

    def options_changed(self, options: 'Options', program: 'Program'):
        self.create_bookmarks_enabled = options.get_boolean(self.OPTION_NAME_CREATE_BOOKMARKS, self.create_bookmarks_enabled)
