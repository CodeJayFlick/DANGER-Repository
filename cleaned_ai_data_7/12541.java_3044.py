class FlowOverride:
    NONE = 0
    BRANCH = 1
    CALL = 2
    CALL_RETURN = 3
    RETURN = 4

    @staticmethod
    def get_flow_override(ordinal):
        for value in [FlowOverride.NONE, FlowOverride.BRANCH, 
                      FlowOverride.CALL, FlowOverride.CALL_RETURN, FlowOverride.RETURN]:
            if value == ordinal:
                return value
        return FlowOverride.NONE


def get_modified_flow_type(original_flow_type: 'FlowType', flow_override: int) -> 'FlowType':
    modified_flow_type = original_flow_type

    if not (flow_override in [FlowOverride.BRANCH, 
                              FlowOverride.CALL, 
                              FlowOverride.CALL_RETURN] or
            isinstance(modified_flow_type, RefType)):
        return modified_flow_type

    # NOTE: The following flow-type overrides assume that a return will always be the last flow pcode-op - since it is the first primary flow pcode-op that will get replaced.
    if flow_override == FlowOverride.BRANCH:
        if isinstance(modified_flow_type, RefType) and modified_flow_type.isJump():
            return modified_flow_type
        elif isinstance(modified_flow_type, RefType) and modified_flow_type.isConditional():
            # assume that we will never start with a complex flow with terminator i.e., CONDITIONAL-JUMP-TERMINATOR
            if modified_flow_type.isTerminal():
                # assume return replaced
                return RefType.CONDITIONAL_ COMPUTED_JMP
            elif isinstance(modified_flow_type, RefType) and modified_flow_type.isComputed():
                return RefType.COMPUTED_JUMP
            else:
                return RefType.UNCONDITIONAL_JUMP
        elif isinstance(modified_flow_type, RefType) and modified_flow_type.isTerminal():
            # assume return replaced
            return RefType. COMPUTED_JMP
        else:
            return RefType.JUMP

    elif flow_override == FlowOverride.CALL:
        if isinstance(modified_flow_type, RefType) and modified_flow_type.isCall():
            return modified_flow_type
        elif isinstance(modified_flow_type, RefType) and modified_flow_type.isConditional():
            # assume original return was preserved
            if modified_flow_type.isTerminal() and (modified_flow_type.isCall() or modified_flow_type.isJump()):
                return RefType.CONDITIONAL_CALL_TERMINATOR
            elif modified_flow_type.isTerminal():
                # assume return replaced
                return RefType. CONDITIONED_COMPUTED_CALL
            else:
                return RefType.CONDITIONAL_CALL
        elif isinstance(modified_flow_type, RefType) and modified_flow_type.isComputed():
            if modified_flow_type.isTerminal() and (modified_flow_type.isCall() or modified_flow_type.isJump()):
                # assume original return was preserved
                return RefType.COMPUTED_CALL_TERMINATOR
            else:
                return RefType. COMPUTED_CALL
        elif isinstance(modified_flow_type, RefType) and modified_flow_type.isTerminal():
            if (modified_flow_type.isCall() or modified_flow_type.isJump()):
                # assume original return was preserved
                return RefType.CALL_TERMINATOR
            else:
                # assume return replaced
                return RefType. COMPUTED_CALL
        else:
            return RefType.UNCONDITIONAL_CALL

    elif flow_override == FlowOverride.CALL_RETURN:
        if isinstance(modified_flow_type, RefType) and modified_flow_type.isConditional():
            if isinstance(modified_flow_type, RefType) and modified_flow_type.isComputed():
                return RefType.CONDITIONAL_COMPUTED_CALL
            else:
                # don't replace
                return modified_flow_type
        elif isinstance(modified_flow_type, RefType) and modified_flow_type.isComputed():
            return RefType.COMPUTED_CALL_TERMINATOR
        elif isinstance(modified_flow_type, RefType) and modified_flow_type.isTerminal():
            # assume return replaced
            return RefType. COMPUTED_CALL_TERMINATOR
        else:
            return RefType.CALL_TERMINATOR

    elif flow_override == FlowOverride.RETURN:
        if isinstance(modified_flow_type, RefType) and modified_flow_type.isConditional():
            return RefType.CONDITIONAL_TERMINATOR
        else:
            return RefType.TERMINATOR


# Example usage:

original_flow_type = 'FlowType'  # Replace with actual flow type value

flow_override_value = FlowOverride.get_flow_override(1)

modified_flow_type = get_modified_flow_type(original_flow_type, flow_override_value)
