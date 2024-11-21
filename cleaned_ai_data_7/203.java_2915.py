class DebuggerWatchActionContext:
    def __init__(self, provider, selected_watches, source_component):
        self.selected_watches = set(selected_watches)
        super().__init__(provider, selected_watches, source_component)

    def get_watch_row(self):
        if len(self.selected_watches) == 1:
            return next(iter(self.selected_watches))
        return None

    def get_watch_rows(self):
        return self.selected_watches
