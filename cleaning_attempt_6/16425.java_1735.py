import math

class ClusterConstant:
    """ Constants for cluster configuration """

    # We only change the value in tests to reduce test time, so they are essentially constant.
    # A failed election will restart in [0, max(heartbeatInterval, 50ms)). If this range is too small,
    # a stale node may frequently issue elections and thus makes the leader step down.
    _election_max_wait_ms = max(ClusterDescriptor().get_config().get_heartbeat_interval_ms(), 50)

    SLOT_NUM = 10000
    HASH_SALT = 2333
    CHECK_ALIVE_TIME_OUT_MS = 1000

    LOG_NUM_IN_BATCH = 100
    RETRY_WAIT_TIME_MS = 10
    THREAD_POLL_WAIT_TERMINATION_TIME_S = 10

    EMPTY_NODE = Node()

    def __init__(self):
        # constant class, no initialization needed
        pass

    @staticmethod
    def get_election_max_wait_ms():
        return ClusterConstant._election_max_wait_ms

    @staticmethod
    @TestOnly
    def set_election_max_wait_ms(election_max_wait_ms):
        ClusterConstant._election_max_wait_ms = election_max_wait_ms


class Node:
    pass  # assuming this is a separate class definition for the Node object
