class MergeProgressModifier:
    def update_progress(self, progress_message=None):
        """Updates the current phase progress area in the default merge panel.
        
        Args:
            progress_message (str): A message indicating what is currently occurring in this phase. Defaults to None.
        """
        pass

    def update_progress(self, current_progress_percentage: int) -> None:
        """Updates the current phase progress area in the default merge panel.
        
        Args:
            current_progress_percentage (int): The progress percentage completed for the current phase. This should be a value from 0 to 100.
        """
        pass

    def update_progress(self, current_progress_percentage: int, progress_message: str) -> None:
        """Updates the current phase progress area in the default merge panel.
        
        Args:
            current_progress_percentage (int): The progress percentage completed for the current phase. This should be a value from 0 to 100.
            progress_message (str): A message indicating what is currently occurring in this phase.
        """
        pass

    def set_in_progress(self, merge_phase: list) -> None:
        """The manager (MergeResolver) for a particular merge phase should call this when its phase or sub-phase begins.
        
        Args:
            merge_phase (list): Identifier for the merge phase to change to in progress status. Should match one that returned by MergeResolver.getPhases()
        """
        pass

    def set_completed(self, merge_phase: list) -> None:
        """The manager (MergeResolver) for a particular merge phase should call this when its phase or sub-phase completes.
        
        Args:
            merge_phase (list): Identifier for the merge phase to change to completed status. Should match one that returned by MergeResolver.getPhases()
        """
        pass
