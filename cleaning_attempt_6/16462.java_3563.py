import logging

class CommitLogTask:
    def __init__(self, log_manager: 'RaftLogManager', leader_commit: int, term: int):
        self.log_manager = log_manager
        self.leader_commit = leader_commit
        self.term = term
        self.logger = logging.getLogger(__name__)

    def register_callback(self, callback):
        self.callback = callback

    def do_commit_log(self):
        if not self.callback:
            self.logger.error("callback is not registered")
            return

        success = self.log_manager.maybe_commit(self.leader_commit, self.term)
        if success:
            self.callback(None)

    def run(self):
        self.do_commit_log()
