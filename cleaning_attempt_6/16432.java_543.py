class CheckConsistencyException(Exception):
    def __init__(self, error_message: str) -> None:
        super().__init__(f"check consistency failed, error message={error_message}")

CHECK_STRONG_CONSISTENCY_EXCEPTION = CheckConsistencyException("strong consistency, sync with leader failed")
CHECK_MID_CONSISTENCY_EXCEPTION = CheckConsistencyException(
    "mid consistency, localAppliedId is smaller than the leaderCommitId"
)
