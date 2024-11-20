class DummyMergeManager:
    def __init__(self, result_program, my_program, original_program, latest_program, latest_change_set, my_change_set):
        pass  # equivalent to super() call in Java

    def set_completed(self, merge_phase: list) -> None:
        pass  # equivalent to empty method body in Java

    def set_in_progress(self, merge_phase: list) -> None:
        pass  # equivalent to empty method body in Java

    def show_progress_icon(self, show: bool) -> None:
        pass  # equivalent to empty method body in Java

    def update_progress(self, current_progress_percentage: int, progress_message: str = '') -> None:
        pass  # equivalent to empty method body in Java

    def update_progress(self, current_progress_percentage: int) -> None:
        pass  # equivalent to empty method body in Java

    def update_progress(self, description: str) -> None:
        pass  # equivalent to empty method body in Java
