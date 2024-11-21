Here is the translation of the given Java code into Python:

```Python
class FidAnalyzer:
    NAME = "Function ID"
    DESCRIPTION = "Finds known functions by hashing."
    
    def __init__(self):
        super().__init__(NAME, DESCRIPTION)
        self.service = FidService()
        self.set_supports_one_time_analysis()
        self.set_priority(AnalysisPriority.FUNCTION_ID_ANALYSIS.before())
        self.score_threshold = self.service.default_score_threshold
        self.multi_score_threshold = self.service.default_multi_name_threshold

    def get_default_enablement(self, program):
        return self.service.can_process(program.language)

    def can_analyze(self, program):
        return self.service.can_process(program.language)

    def added(self, program, address_set_view, task_monitor, message_log):
        if not self.service.can_process(program.language):
            print("No FID Libraries apply for language " + str(program.language))
            return False
        cmd = ApplyFidEntriesCommand(address_set_view, self.score_threshold,
                                      self.multi_score_threshold, self.always_apply_fid_labels,
                                      self.create_bookmarks_enabled)
        cmd.apply_to(program, task_monitor)

    def register_options(self, options, program):
        options.register_option("Score Threshold", self.service.default_score_threshold,
                                 None, "The minimum score that a potential match must meet to be labeled by the analyzer.")
        options.register_option("Multiple Match Threshold",
                                 self.service.default_multi_name_threshold, None,
                                 "If there are multiple conflicting matches for a function, its score must exceed this secondary threshold in order to be labeled by the analyzer")
        options.register_option("Always Apply FID Labels", self.always_apply_fid_labels, None,
                                 "Enable this option to always apply FID labels at functions regardless of existing labels at that function.")
        options.register_option("Create Analysis Bookmarks", self.create_bookmarks_enabled, None,
                                 "If checked, an analysis bookmark will be created for each function which was matched against one or more known library functions.")

    def options_changed(self, options, program):
        self.score_threshold = options.get_float("Score Threshold",
                                                  self.service.default_score_threshold)
        self.multi_score_threshold = options.get_float(
            "Multiple Match Threshold", self.service.default_multi_name_threshold
        )
        self.always_apply_fid_labels = options.get_boolean(
            "Always Apply FID Labels", self.always_apply_fid_labels
        )
        self.create_bookmarks_enabled = options.get_boolean(
            "Create Analysis Bookmarks", self.create_bookmarks_enabled
        )


class FidService:
    def __init__(self):
        pass

    @property
    def default_score_threshold(self):
        return 0.5

    @property
    def default_multi_name_threshold(self):
        return 1.2


class ApplyFidEntriesCommand:
    def __init__(self, address_set_view, score_threshold, multi_score_threshold,
                 always_apply_fid_labels, create_bookmarks_enabled):
        self.address_set_view = address_set_view
        self.score_threshold = score_threshold
        self.multi_score_threshold = multi_score_threshold
        self.always_apply_fid_labels = always_apply_fid_labels
        self.create_bookmarks_enabled = create_bookmarks_enabled

    def apply_to(self, program, task_monitor):
        pass


class AnalysisPriority:
    FUNCTION_ID_ANALYSIS = 1


FidAnalyzer().added(None, None, None, None)
```

Please note that this is a direct translation of the given Java code into Python. The functionality and logic might not be exactly equivalent due to differences in syntax and semantics between languages.