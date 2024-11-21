class BatchPlan:
    def __init__(self):
        self._sub_plans_executed = []

    def set_sub_plan_executed(self, i: int) -> None:
        """Mark the sub-plan at position i as executed."""
        if 0 <= i < len(self._sub_plans_executed):
            self._sub_plans_executed[i] = True
        else:
            raise IndexError(f"Index {i} out of range")

    def unset_sub_plan_executed(self, i: int) -> None:
        """Mark the sub-plan at position i as not executed."""
        if 0 <= i < len(self._sub_plans_executed):
            self._sub_plans_executed[i] = False
        else:
            raise IndexError(f"Index {i} out of range")

    def is_sub_plan_executed(self, i: int) -> bool:
        """Whether the sub-plan at position i has been executed."""
        if 0 <= i < len(self._sub_plans_executed):
            return self._sub_plans_executed[i]
        else:
            raise IndexError(f"Index {i} out of range")

    @property
    def batch_size(self) -> int:
        """Return how many sub-plans are in the plan."""
        return len(self._sub_plans_executed)

    @property
    def results(self) -> dict:
        """Return execution status for each path"""
        return {i: TSStatus() for i in range(len(self._sub_plans_executed))}

    @property
    def prefix_paths(self) -> list:
        """Return prefix paths of all sub-plans"""
        # Note that this property does not actually store the prefix paths,
        # but rather returns an empty list. You would need to modify this class
        # if you want to store and return actual prefix path data.
        return []
