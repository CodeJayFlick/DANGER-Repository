import logging

class EventValidator:
    def __init__(self):
        self.model = None
        self.processes = {}
        self.threads = {}
        self.modules = {}

    def event(self, object, thread, type, description, parameters):
        if isinstance(object, TargetProcess):
            self.validate_created(type.name(), "process", parameters)
        elif isinstance(object, TargetThread):
            self.validate_created(type.name(), "thread", parameters)
        elif isinstance(object, TargetModule):
            self.validate_created(type.name(), "module", parameters)

    def validate_created(self, event_type, object_type, parameters):
        if not self.processes:
            return
        for obj in parameters[1:]:
            if isinstance(obj, TargetProcess):
                observation = NoObservation(obj)
            elif isinstance(obj, TargetThread):
                observation = UseObservation(event_type, obj)
            elif isinstance(obj, TargetModule):
                observation = CreatedObservation(event_type, obj)

    def validate_destroyed(self, event_type, object_type, parameters):
        if not self.processes:
            return
        for obj in parameters[1:]:
            if isinstance(obj, TargetProcess):
                observation = DestroyedObservation(event_type, obj)
            elif isinstance(obj, TargetThread):
                observation = UseObservation(event_type, obj)
            elif isinstance(obj, TargetModule):
                observation = CreatedObservation(event_type, obj)

    def close(self):
        pass

class NoObservation:
    def __init__(self, object):
        self.object = object
        self.event = "[none]"

    def in_parameter(self, event):
        return UseObservation(event, self.object)

    def in_created(self, event):
        return CreatedObservation(event, self.object)

    def in_destroyed(self, event):
        return DestroyedObservation(event, self.object)


class UseObservation:
    def __init__(self, event, object):
        self.event = event
        self.object = object

    def in_parameter(self, event):
        return this

    def in_created(self, event):
        raise AssertionError(f"Observed {event} for {object.get_joined_path('.') } before {event}")

    def in_destroyed(self, event):
        return DestroyedObservation(event, self.object)


class CreatedObservation:
    def __init__(self, event, object):
        self.event = event
        self.object = object

    def in_parameter(self, event):
        return this

    def in_created(self, event):
        raise AssertionError(f"Observed double-{event} of {object.get_joined_path('.') }")

    def in_destroyed(self, event):
        return DestroyedObservation(event, self.object)


class DestroyedObservation:
    def __init__(self, event, object):
        self.event = event
        self.object = object

    def in_parameter(self, event):
        raise AssertionError(f"Observed {event} of {object.get_joined_path('.') } after {event}")

    def in_created(self, event):
        return CreatedObservation(event, self.object)

    def in_destroyed(self, event):
        raise AssertionError(f"Observed double-{event} of {object.get_joined_path('.') }")
