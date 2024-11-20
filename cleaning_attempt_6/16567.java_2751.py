import logging
from typing import List

class LogCatchUpInBatchHandler:
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.append_succeed = None  # type: AtomicBoolean
        self.raft_member = None  # type: RaftMember
        self.member_name = None  # type: str
        self.follower = None  # type: Node
        self.logs = []  # type: List[ByteBuffer]

    def set_append_succeed(self, append_succeed):
        self.append_succeed = append_succeed

    def set_raft_member(self, raft_member):
        self.raft_member = raft_member
        self.member_name = raft_member.name

    def set_follower(self, follower):
        self.follower = follower

    def set_logs(self, logs):
        self.logs = logs

    async def on_complete(self, response: int) -> None:
        if response == RESPONSE_AGREE:
            with self.append_succeed:
                self.append_succeed.set(True)
                self.append_succeed.notify_all()
            self.logger.debug(f"{self.member_name}: Succeeded to send logs, size is {len(self.logs)}")

        elif response == RESPONSE_LOG_MISMATCH:
            self.logger.error(f"{self.member_name}: Log mismatch occurred when sending logs, whose size is {len(self.logs)}")
            with self.append_succeed:
                self.append_succeed.notify_all()

        else:  # term has updated
            self.logger.debug(
                f"{self.member_name}: Received a rejection because term is updated to {response} when sending {len(self.logs)} logs"
            )
            self.raft_member.step_down(response, False)
            with self.append_succeed:
                self.append_succeed.notify_all()
            self.logger.warn(f"{self.member_name}: Catch-up with {len(self.logs)} logs aborted because leadership is lost")

    async def on_error(self, exception: Exception) -> None:
        with self.append_succeed:
            self.append_succeed.notify_all()
        self.logger.warn(
            f"{self.member_name}: Catch-up fails when sending log, whose size is {len(self.logs)}, error: {exception}"
        )
