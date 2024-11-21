class AbstractListingMerger:
    def __init__(self, listing_merge_mgr):
        self.listing_merge_mgr = listing_merge_mgr
        self.init()

    def init(self):
        self.error_buf = StringBuffer()
        self.info_buf = StringBuffer()
        self.merge_manager = self.listing_merge_mgr.merge_manager
        self.listing_merge_panel = self.listing_merge_mgr.get_listing_merge_panel()
        self.conflict_info_panel = self.listing_merge_mgr.get_conflict_info_panel()

        self.result_pgm = self.listing_merge_mgr.programs[0]
        self.original_pgm = self.listing_merge_mgr.programs[1]
        self.latest_pgm = self.listing_merge_mgr.programs[2]
        self.my_pgm = self.listing_merge_mgr.programs[3]

        self.result_address_factory = self.result_pgm.get_address_factory()

        self.diff_original_latest = self.listing_merge_mgr.diff_original_latest
        self.diff_original_my = self.listing_merge_mgr.diff_original_my
        self.diff_latest_my = self.listing_merge_mgr.diff_latest_my

    def get_program_index(self, pgm):
        if pgm == self.result_pgm:
            return 0
        elif pgm == self.latest_pgm:
            return 2
        elif pgm == self.my_pgm:
            return 3
        elif pgm == self.original_pgm:
            return 1
        else:
            return -1

    def get_program_for_conflict_option(self, chosen_conflict_option):
        if chosen_conflict_option == 0:  # KEEP_LATEST
            return self.latest_pgm
        elif chosen_conflict_option == 2:  # KEEP_MY
            return self.my_pgm
        elif chosen_conflict_option == 1:  # KEEP_ORIGINAL
            return self.original_pgm
        else:
            return None

    def limit_to_start_of_code_units(self, program, initial_set):
        listing = program.get_listing()
        address_set = set()

        for addr in initial_set:
            code_unit = listing.get_code_unit_at(addr)
            if code_unit is not None:
                address_set.add_range(addr, addr)

        return address_set

    def get_code_unit_address_set(self, addrs):
        code_set = set()

        code_set.update(DiffUtility.get_code_unit_set(addrs, self.latest_pgm))
        code_set.update(DiffUtility.get_code_unit_set(addrs, self.my_pgm))
        code_set.update(DiffUtility.get_code_unit_set(addrs, self.original_pgm))

        return code_set

    def clear_resolve_errors(self):
        if len(self.error_buf) > 0:
            self.error_buf = StringBuffer()

    def show_resolve_errors(self):
        if len(self.error_buf) > 0:
            try:
                SwingUtilities.invokeLater(lambda: ReadTextDialog("Merge Errors", str(self.error_buf)).show())
            except (InterruptedException, InvocationTargetException as e):
                raise AssertException(e)

    def clear_resolve_info(self):
        if len(self.info_buf) > 0:
            self.info_buf = StringBuffer()

    def show_resolve_info(self):
        if len(self.info_buf) > 0:
            try:
                SwingUtilities.invokeLater(lambda: ReadTextDialog("Merge Information", str(self.info_buf)).show())
            except (InterruptedException, InvocationTargetException as e):
                raise AssertException(e)

    @staticmethod
    def same(o1, o2):
        if o1 is None:
            return o2 is None
        return o1.equals(o2)

    def apply(self):
        self.num_conflicts_resolved = 0

        if self.current_conflict_panel is not None:
            self.num_conflicts_resolved = self.current_conflict_panel.get_num_conflicts_resolved()
            if self.current_conflict_panel.all_choices_are_resolved():
                self.current_conflict_panel.remove_all_listeners()
                return True
            else:
                return False

        return True

    def cancel(self):
        pass  # Do nothing

    @property
    def num_conflicts_resolved(self):
        return self.num_conflicts_resolved

    def increment_progress(self, increment):
        progress_range = self.max_phase_progress_percentage - self.min_phase_progress_percentage
        self.change_num += increment
        granularity = (self.total_changes / progress_range) + 1

        if self.change_num % granularity == 0:
            if self.total_changes <= 0:
                self.total_changes = 1
            self.merge_manager.update_progress((int)(self.min_phase_progress_percentage + ((self.change_num * progress_range) // self.total_changes)))

    def update_progress_message(self, message):
        self.merge_manager.update_progress(message)

    def update_progress(self, my_percent_complete):
        progress_range = self.max_phase_progress_percentage - self.min_phase_progress_percentage
        my_progress = (my_percent_complete * progress_range) / 100

        self.merge_manager.update_progress(self.min_phase_progress_percentage + my_progress)
