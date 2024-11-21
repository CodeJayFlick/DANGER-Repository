class DebuggerTimeProvider:
    def __init__(self, plugin):
        self.plugin = plugin
        # ... (rest of the constructor)

    @property
    def main_panel(self):
        if not hasattr(self, '_main_panel'):
            self._main_panel = JPanel()
            self._main_panel.setLayout(BorderLayout())
            snapshot_table = GTable(EnumeratedColumnTableModel('Snapshots', SnapshotTableColumns))
            snapshot_table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION)
            self._main_panel.add(ScrollPane(snapshot_table), BorderLayout.CENTER)

            # ... (rest of the build_main_panel method)

    def add_local_action(self, action):
        super().add_local_action(action)

    @property
    def component(self):
        return self.main_panel

    def get_action_context(self, event):
        if not hasattr(self, '_my_action_context'):
            return super().get_action_context(event)
        else:
            return self._my_action_context

    # ... (rest of the class methods)

class SnapshotTableColumns(Enum):
    SNAP = ('Snap', Long, lambda row: row.get_snap())
    TIMESTAMP = ('Timestamp', str, lambda row: row.get_timestamp())
    EVENT_THREAD = ('Event Thread', str, lambda row: row.get_event_thread_name())
    SCHEDULE = ('Schedule', str, lambda row: row.get_schedule())
    DESCRIPTION = ('Description', str, lambda row: row.get_description(), lambda row, value: row.set_description(value))

class SnapshotRow:
    def __init__(self, trace, snapshot):
        self.trace = trace
        self.snapshot = snapshot

    @property
    def snap(self):
        return self.snapshot.key()

    @snap.setter
    def snap(self, value):
        # ... (set the snapshot key)

    # ... (rest of the class methods)
