class TableUpdateJob:
    def __init__(self, model: 'ThreadedTableModel', monitor):
        self.model = model
        self.monitor = monitor
        self.currentState = JobState.NOT_RUNNING
        self.pendingRequestedState = None
        self.isFired = False

    @staticmethod
    def enum_job_state():
        return {
            "NOT RUNNING": 0,
            "LOADING": 1,
            "FILTERING": 2,
            "ADD REMOVING": 3,
            "SORTING": 4,
            "APPLYING": 5,
            "DONE": 6
        }

    def set_data(self, data: 'TableData'):
        self.source_data = data

    def set_force_filter(self, force):
        self.do_force_filter = force

    def run(self):
        while True:
            try:
                if not self.process_state(self.currentState):
                    break
            except CancelledException as e:
                print(f"Unexpected Exception: {e.message}")

    def reload(self):
        if self.currentState != JobState.NOT_RUNNING:
            raise IllegalStateException("Cannot reload once a job starts")
        self.isFired = False  # reset the cancel flag, since we are reloading
        self.reload_data = True

    def add_remove(self, item: 'AddRemoveListItem', max_add_remove_count):
        if self.currentState != JobState.NOT_RUNNING:
            raise IllegalStateException("Cannot add or remove once a job starts")
        if self.reload_data:
            return  # no need to process add/remove since we are reloading
        if len(self.add_remove_list) > max_add_remove_count:
            self.reload()
            return
        self.add_remove_list.append(item)

    def request_sort(self, new_sort_context: 'TableSortingContext', force_sort):
        if self.currentState == JobState.DONE:
            return False  # job is done and cannot be processed further
        this.do_force_sort = force_sort
        this.new_sort_context = new_sort_context
        if has_sorted():
            monitor.cancel()
            pending_requested_state = JobState.SORTING

    def request_filter(self):
        if self.currentState == JobState.DONE:
            return False  # job is done and cannot be processed further
        if has_filtered():
            monitor.cancel()
            pending_requested_state = JobState.FILTERING

    def get_next_state(self, state: 'JobState'):
        match state:
            case JobState.NOT_RUNNING:
                return JobState.LOADING
            case JobState.LOADING:
                return JobState.FILTERING
            case JobState.FILTERING:
                return JobState.ADD_REMOVING
            case JobState.ADD_REMOVING:
                return JobState.SORTING
            case JobState.SORTING:
                return JobState.APPLYING
            case _:
                return JobState.DONE

    def process_state(self, state: 'JobState'):
        match state:
            case JobState.LOADING:
                self.load_data()
                break
            case JobState.FILTERING:
                self.do_filter_data()
                break
            case JobState.ADD_REMOVING:
                self.do_process_add_removes()
                break
            case JobState.SORTING:
                self.sort_data()
                break
            case JobState.APPLYING:
                self.apply_data()
                break

    def load_data(self):
        if self.reload_data:
            # Load the data from scratch
            new_data = self.model.load(monitor)
            source_data = TableData.create_full_dataset(new_data)
        else:
            # No loading; just updating
            source_data = pick_existing_table_data()
            last_sort_context = source_data.get_sort_context()

    def do_filter_data(self):
        if can_reuse_current_filtered_data():
            copy_current_filter_data()
            return

        filter_source_data = self.source_data
        size = len(filter_source_data)
        monitor.set_message(f"Filtering {self.model.name} ({size} rows)...")
        list_ = filter_source_data.get_data()
        result = self.model.do_filter(list_, last_sort_context, monitor)

    def apply_data(self):
        all_data = source_data.get_root_data()
        try:
            SwingUtilities.invokeLater(lambda: model.set_model_state(all_data, updated_data))
        except Exception as e:
            print(f"Unexpected Exception: {e.message}")

    def cancel(self):
        self.isFired = True  # let the job die, ignoring any issues that may arise
        pending_requested_state = JobState.DONE
        monitor.cancel()

    @property
    def state_history_string(self) -> str:
        return '\n'.join(map(str, debug_state_history))

# Helper functions

def has_sorted():
    if self.do_force_sort or new_sort_context is not None and last_sort_context != new_sort_context:
        return True
    else:
        return False

def can_reuse_current_filtered_data() -> bool:
    # We can skip filtering if: 
    # - we have not been told to filter
    # - the table is not currently filtered, or is filtered, but 
    #   -- the source data that the filtered data is based upon hasn't changed 
    #   -- the filter hasn't changed

    return self.do_force_filter and current_table_data.is_unrelated_to(source_data) and current_table_data.matches_filter(applied_or_pending_filter)

def copy_current_filter_data():
    TableData current_filtered_data = getCurrentFilteredData()
    updated_data = current_filtered_data.copy(source_data)
    last_sort_context = updated_data.get_sort_context()

# Other helper functions
