class JdiBreakpointInfo:
    def __init__(self, request):
        self.request = request
        if isinstance(request, BreakpointRequest):
            self.type = 'BREAKPOINT'
        elif isinstance(request, AccessWatchpointRequest):
            self.type = 'ACCESS_WATCHPOINT'
        elif isinstance(request, ModificationWatchpointRequest):
            self.type = 'MODIFICATION_WATCHPOINT'

    def __hash__(self):
        return hash(self.request)

    def __str__(self):
        return str(self.request)

    def __eq__(self, other):
        if not isinstance(other, JdiBreakpointInfo):
            return False
        if self.request != other.request:
            return False
        return True

    @property
    def type(self):
        return self.type_

    @type.setter
    def type_(self, value):
        self.type_ = value

    @property
    def request(self):
        return self._request

    @request.setter
    def request(self, value):
        self._request = value

    @property
    def object_filter(self):
        return self.object_filter_

    @object_filter.setter
    def object_filter_(self, value):
        self.object_filter_ = value

    @property
    def thread_filter(self):
        return self.thread_filter_

    @thread_filter.setter
    def thread_filter_(self, value):
        self.thread_filter_ = value

    @property
    def class_filter(self):
        return self.class_filter_

    @class_filter.setter
    def class_filter_(self, value):
        self.class_filter_ = value

    @property
    def filter_pattern(self):
        return self.filter_pattern_

    @filter_pattern.setter
    def filter_pattern_(self, value):
        self.filter_pattern_ = value

    def is_enabled(self):
        if isinstance(self.request, BreakpointRequest):
            return (self.request).is_enabled()
        elif isinstance(self.request, WatchpointRequest):
            return (self.request).is_enabled()
        else:
            return False

    def set_enabled(self, b):
        if isinstance(self.request, BreakpointRequest):
            breakpoint = self.request
            if b:
                breakpoint.enable()
            else:
                breakpoint.disable()
        elif isinstance(self.request, WatchpointRequest):
            watchpoint = self.request
            if b:
                watchpoint.enable()
            else:
                watchpoint.disable()

class ReferenceType:
    pass

class ObjectReference:
    pass

class ThreadReference:
    pass

class ReferenceType:
    pass

class BreakpointRequest:
    def __init__(self, enabled):
        self.enabled = enabled

    @property
    def is_enabled(self):
        return self.enabled

    def enable(self):
        self.enabled = True

    def disable(self):
        self.enabled = False


class AccessWatchpointRequest(BreakpointRequest):
    pass


class ModificationWatchpointRequest(BreakpointRequest):
    pass
