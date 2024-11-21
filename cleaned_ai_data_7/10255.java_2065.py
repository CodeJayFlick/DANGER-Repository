import logging
from io import StringIO
from functools import lru_cache

class TestReportingException(Exception):
    def __init__(self, thread_name: str, t: Exception, test_thread_trace=None) -> None:
        self.thread_name = thread_name
        self.t = Objects.requireNonNull(t)
        self.test_thread_trace = test_thread_trace if test_thread_trace is not None else []

    @classmethod
    def from_swing_thread(cls, message: str, t: Exception) -> 'TestReportingException':
        test_thread_trace = None
        if TestThread.is_test_thread():
            test Throwable = ReflectionUtilities.createThrowableWithStackOlderThan(TestReportingException)
            test_thread_trace = test.get_stacktrace()
            test_thread_trace = TestThread.filter_trace(test_thread_trace)

            awt_thread_trace = t.get_stacktrace()
            awt_thread_trace = TestThread.filter_trace(awt_thread_trace)
            t.set_stacktrace(awt_thread_trace)

        e = cls("AWT-EventQueue-0", t, test_thread_trace)
        e.user_message = message
        return e

    @classmethod
    def get_swing_thread_trace_string(cls, throwable: Exception) -> str:
        trace = throwable.get_stacktrace()
        filtered = ReflectionUtilities.filter_stacktrace(trace, cls.SWING_STACK_ELEMENT_PATTERNS)

        className = throwable.__class__.__name__
        message = throwable.getMessage()

        if message is not None:
            message = f"{className}: {message}"
        else:
            message = className

        string_writer = StringIO()
        writer = logging.StreamHandler(string_writer)
        writer.write(message + "\n")

        cls.print_trace(filtered, writer)

        return string_writer.getvalue()

    def print_stacktrace(self) -> None:
        trace = self.build_stacktrace_string()
        print(trace)

    @lru_cache(maxsize=None)
    def get_stacktrace(self) -> list:
        # this is overridden for clients that do not call print_stacktrace
        return self.t.get_stacktrace()

    def get_message(self) -> str:
        # this is overridden for clients that do not call print_stacktrace
        return f"(See log for more stack trace info)\n\n{self.generate_messge()}"

    @lru_cache(maxsize=None)
    def build_stacktrace_string(self) -> str:
        message = self.generate_message()

        string_writer = StringIO()
        writer = logging.StreamHandler(string_writer)

        if self.user_message is not None:
            writer.write(f"{self.user_message}\n")

        trace = self.t.get_stacktrace()
        trace = self.filter_trace(trace)
        cls.print_trace(trace, writer)

        if self.test_thread_trace is not None:
            writer.write("\nTest thread stack at that time:\n")
            cls.print_trace(self.test_thread_trace, writer)

        return string_writer.getvalue()

    def add_all_cause_exceptions(self) -> None:
        self.add_cause_exception(self.t)

    @lru_cache(maxsize=None)
    def generate_message(self) -> str:
        message = self.t.getMessage()
        if message is not None:
            return f"{self.t.__class__.__name__}: {message} (thread '{self.thread_name}')"
        else:
            return ""

    @classmethod
    @lru_cache(maxsize=None)
    def add_cause_exception(cls, currentThrowable: Exception) -> None:
        theCause = currentThrowable.getCause()
        if theCause is not None:
            defaultMessage = theCause.__class__.__name__
            message = theCause.getMessage() if theCause.getMessage() is not None else defaultMessage
            writer.write(f"\nCaused By:\n\t{message}\n")

            causeByTrace = theCause.get_stacktrace()
            causeByTrace = cls.filter_trace(causeByTrace)
            cls.print_trace(causeByTrace, writer)

            cls.add_cause_exception(theCause, writer)

    @classmethod
    def print_trace(cls, trace: list, writer) -> None:
        for element in trace:
            writer.write(f"\tat {element}\n")

class TestThread:
    @staticmethod
    def is_test_thread() -> bool:
        return True

    @staticmethod
    @lru_cache(maxsize=None)
    def filter_trace(trace: list) -> list:
        if "AWT-EventQueue" in trace[0]:
            filtered = ReflectionUtilities.filter_stacktrace(trace, TestReportingException.SWING_STACK_ELEMENT_PATTERNS)
            return filtered
        else:
            filtered = ReflectionUtilities.filter_stacktrace(trace, TestReportingException.GENERAL_USELESS_STACK_ELEMET_PATTERNS)
            return filtered

    @staticmethod
    def createThrowableWithStackOlderThan(cls):
        pass

class Utilities:
    class ReflectionUtilities:
        @classmethod
        def filter_stacktrace(cls, trace: list, patterns) -> list:
            result = []
            for element in trace:
                if not any(pattern in str(element) for pattern in patterns):
                    result.append(element)
            return result

        @staticmethod
        def createThrowableWithStackOlderThan(cls):
            pass
