class StringEventsTask:
    def __init__(self, string_model, options, events):
        self.string_model = string_model
        self.options = options
        self.events = events

    def run(self):
        for event in self.events:
            event.process(self.string_model, self.options)
