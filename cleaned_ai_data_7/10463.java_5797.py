class MultipleCauses(Exception):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.causes = []

    def add_cause(self, cause):
        self.causes.append(cause)

    def get_causes(self):
        return self.causes

    @classmethod
    def has_multiple(cls, e):
        while True:
            if isinstance(e, MultipleCauses):
                return True
            elif e is None or not hasattr(e, 'getCause'):
                break
            e = e.getCause()
        return False

    @staticmethod
    def print_tree(out, prefix, e):
        out.write(prefix)
        try:
            e.print_stack_trace(out)
        except AttributeError:
            pass  # If the exception doesn't have a print_stack_trace method, just ignore it.
        if MultipleCauses.has_multiple(e):
            report = None
            while True:
                cause = e.getCause()
                if isinstance(cause, MultipleCauses):
                    report = cause
                    break
                elif cause is not None and hasattr(cause, 'getCause'):
                    e = cause
                else:
                    break
            for t in report.get_causes():
                MultipleCauses.print_tree(out, prefix + ">", t)

    @staticmethod
    def print_stack_trace(out, e):
        try:
            e.with_traceback(sys._getframe(1)).print_stack_trace(out)
        except AttributeError:
            pass  # If the exception doesn't have a print_stack_trace method, just ignore it.

def iter_causes(exc):
    cause = exc.getCause()
    if isinstance(cause, MultipleCauses):
        return tuple(cause.get_causes())
    else:
        return (cause,)
