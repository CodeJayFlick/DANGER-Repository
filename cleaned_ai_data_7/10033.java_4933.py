import datetime
from threading import Lock


class SpyEventRecorder:
    def __init__(self, recorder_name):
        self.recorder_name = recorder_name
        self.events = []
        self.buffered = True
        self.lock = Lock()
        self.global_id = 0

    def set_buffered(self, buffered):
        with self.lock:
            self.buffered = buffered

    def record(self, message):
        event = SpyEvent(message)
        if self.buffered:
            with self.lock:
                self.events.append(event)
        else:
            print(f"({event.id}) {datetime.datetime.now()} {message}")

    def record(self, message, *args):
        formatted_message = message.format(*args)
        self.record(formatted_message)

    def dump_events(self):
        event_strings = [str(event) for event in self.events]
        msg_string = f"Recorded Events - {self.recorder_name}\n{os.linesep.join(event_strings)}"
        print(msg_string)

    def __str__(self):
        return str(self.dump_events())

    class SpyEvent:
        PADDING = "           "
        DATE_FORMAT = datetime.datetime.now().strftime("%T")

        def __init__(self, message):
            self.message = message
            global_id = 0
            self.id = global_id + 1

        def __str__(self):
            id_str = str(self.id).rjust(len(SpyEvent.PADDING))
            return f"({self.id}) {SpyEvent.DATE_FORMAT} {self.message}"
