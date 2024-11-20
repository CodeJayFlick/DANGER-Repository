class DummyArchiveMergeManager:
    def __init__(self, result_dt_archive: object, my_dt_archive: object,
                 original_dt_archive: object, latest_dt_archive: object,
                 latest_change_set: object, my_change_set: object):
        pass

    def set_completed(self, merge_phase: list) -> None:
        pass

    def set_in_progress(self, merge_phase: list) -> None:
        pass

    def show_progress_icon(self, show: bool) -> None:
        pass

    def update_progress(self, current_progress_percentage: int, progress_message: str = '') -> None:
        pass

    def update_progress(self, current_progress_percentage: int) -> None:
        pass

    def update_progress(self, description: str) -> None:
        pass
