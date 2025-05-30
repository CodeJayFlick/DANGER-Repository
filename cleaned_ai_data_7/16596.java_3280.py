class Response:
    RESPONSE_AGREE = -1
    RESPONSE_LOG_MISMATCH = -2
    RESPONSE_REJECT = -3
    RESPONSE_PARTITION_TABLE_UNAVAILABLE = -4
    RESPONSE_IDENTIFIER_CONFLICT = -5
    RESPONSE_NO_CONNECTION = -6
    RESPONSE_LEADER_STILL_ONLINE = -7
    RESPONSE_CLUSTER_TOO_SMALL = -8
    RESPONSE_NEW_NODE_PARAMETER_CONFLICT = -9
    RESPONSE_DATA_MIGRATION_NOT_FINISH = -10
    RESPONSE_NODE_IS_NOT_IN_GROUP = -11
    RESPONSE_NULL = float('-inf')

    def __init__(self):
        pass

# Example usage:
response = Response()
print(response.RESPONSE_AGREE)  # Output: -1
