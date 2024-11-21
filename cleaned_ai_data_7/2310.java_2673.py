class EventSequenceListener:
    class EventRecord:
        def __init__(self, object, event_thread, type, description, parameters):
            self.object = object
            self.event_thread = event_thread
            self.type = type
            self.description = description
            self.parameters = parameters

        def __str__(self):
            return f"<EventRecord obj={self.object} thread={self.event_thread} type={self.type} desc='{self.description}' params={self.parameters}>"

        def __eq__(self, other):
            if not isinstance(other, EventRecord):
                return False
            if self.object != other.object:
                return False
            if self.event_thread != other.event_thread:
                return False
            if self.type != other.type:
                return False
            if self.description != other.description:
                return False
            if self.parameters != other.parameters:
                return False
            return True

        def __hash__(self):
            return hash((self.object, self.event_thread, self.type, self.description, self.parameters))

    events = []

    def event(self, object, event_thread, type, description, parameters):
        self.events.append(EventRecord(object, event_thread, type, description, parameters))
