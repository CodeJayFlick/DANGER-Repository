class EmulateExecutionState:
    STOPPED = "STOPPED"
    BREAKPOINT = "BREAKPOINT"
    INSTRUCTION_DECODE = "INSTRUCTION_DECODE"
    EXECUTE = "EXECUTE"
    FAULT = "FAULT"

# You can use this class like a dictionary
print(EmulateExecutionState.STOPPED)  # prints: STOPPED
