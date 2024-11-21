class TraceRecorderListener:
    def register_bank_mapped(self, recorder):
        pass

    def register_accessibility_changed(self, recorder):
        pass

    def process_memory_accessibility_changed(self, recorder):
        pass

    def recording_stopped(self, recorder):
        pass

    def snap_advanced(self, recorder, snap):
        pass
