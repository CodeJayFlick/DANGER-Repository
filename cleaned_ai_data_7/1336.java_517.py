class GdbConsoleExecCommand:
    class CompletesWithRunning(enum.Enum):
        CANNOT = 0
        CAN = 1
        MUST = 2

        def __init__(self, completion_class):
            self.completion_class = completion_class

        @abstractmethod
        def handle_running(self, event, pending):
            pass


class Output(enum.Enum):
    CONSOLE = 0
    CAPTURE = 1


def __init__(manager: GdbManagerImpl, thread_id: int, frame_id: int, command: str, output_to: Output, completes_with_running: CompletesWithRunning):
    self.manager = manager
    self.thread_id = thread_id
    self.frame_id = frame_id
    self.command = command
    self.output_to = output_to
    self.completes_with_running = completes_with_running


def get_interpreter(self) -> Interpreter:
    return Interpreter.MI2


def encode(self, thread_part: str, frame_part: str):
    if self.get_interpreter() == Interpreter.CLI:
        return self.command

    return f"-interpreter-exec{thread_part}{frame_part} console \"{StringEscapeUtils.escapeJava(self.command)}\""


def handle(self, event: GdbEvent, pending: GdbPendingCommand) -> bool:
    if self.get_interpreter() == Interpreter.CLI:
        if isinstance(event, GdbConsoleOutputEvent):
            return True

    elif isinstance(event, GdbCommandRunningEvent):
        return self.completes_with_running.handle_running(event, pending)

    elif isinstance(event, AbstractGdbCompletedCommandEvent):
        pending.claim(event)
        return True

    elif isinstance(event, GdbConsoleOutputEvent) and event.get_interpreter() == Interpreter.MI2:
        if ">".equals(event.get_output().trim()) and not self.command.trim().startswith("ec"):
            self.manager.inject_input(Interpreter.MI2, "end\n")
            self.manager.synthesize_console_out(Channel.STDERR,
                                                  f"Ghidra GDB Agent: Multi-line / follow-up input is not currently supported. I just typed 'end' for you.\n")

        if self.output_to == Output.CAPTURE:
            pending.steal(event)

    return False


def complete(self, pending: GdbPendingCommand) -> str:
    if self.get_interpreter() == Interpreter.CLI:
        return None

    # MI2
    pending.check_completion(self.completes_with_running.completion_class)

    if self.output_to == Output.CONSOLE:
        return None

    builder = StringBuilder()
    for event in pending.findall(GdbConsoleOutputEvent):
        builder.append(event.get_output())

    return str(builder)


def get_output_to(self) -> Output:
    return self.output_to


def is_focus_internally_driven(self) -> bool:
    return self.output_to == Output.CAPTURE
