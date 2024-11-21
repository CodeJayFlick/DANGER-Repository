class FollowFlowBackFrom:
    def __init__(self):
        pass

    @staticmethod
    def get_flows_to(address_set_view_flow_addresses):
        return address_set_view_flow_addresses

    @staticmethod
    def follow_all_flows():
        return "followAllFlows"

    @staticmethod
    def follow_only_unconditional_calls():
        return "followOnlyUnconditionalCalls"

    @staticmethod
    def follow_only_conditional_jumps():
        return "followOnlyConditionalJumps"

    @staticmethod
    def follow_only_computed_jumps():
        return "followOnlyComputedJumps"

    @staticmethod
    def get_flows_to(address_set, flow_type):
        if flow_type == FollowFlowBackFrom.follow_all_flows:
            # your code here

        elif flow_type == FollowFlowBackFrom.follow_only_unconditional_calls:
            # your code here

        elif flow_type == FollowFlowBackFrom.follow_only_conditional_jumps:
            # your code here

        elif flow_type == FollowFlowBackFrom.follow_only_computed_jumps:
            # your code here
