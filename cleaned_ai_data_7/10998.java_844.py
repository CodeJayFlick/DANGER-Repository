class DefaultCheckinHandler:
    def __init__(self, comment: str, keep_checked_out: bool, create_keep_file: bool):
        self.comment = comment
        self.keep_checked_out = keep_checked_out
        self.create_keep_file = create_keep_file

    def get_comment(self) -> str:
        return self.comment

    def keep_checked_out(self) -> bool:
        return self.keep_checked_out

    def create_keep_file(self) -> bool:
        return self.create_keep_file
