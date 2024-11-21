Here is the translation of the given Java code into equivalent Python:

```Python
import datetime as dt
from typing import Dict, Any

class DomainEventDisplayPlugin:
    def __init__(self):
        self.current_program = None
        self.provider = None
        self.event_ht: Dict[int, str] = {}
        self.pad_string = ""

    @property
    def font(self) -> Font:
        return self.provider.font if self.provider else None

    @font.setter
    def font(self, value):
        if self.provider:
            self.provider.font = value
            # todo: implement tool.set_config_changed(True)

    def process_event(self, event):
        if isinstance(event, ProgramActivatedPluginEvent):
            new_prog = event.active_program
            if self.current_program is not None:
                self.current_program.remove_listener(self)
            if new_prog is not None:
                new_prog.add_listener(self)

    def dispose(self):
        if self.current_program is not None:
            self.current_program.remove_listener(self)

    def domain_object_changed(self, event: DomainObjectChangedEvent):
        if self.provider and self.provider.is_visible():
            self.update(event)

    def update(self, event: DomainObjectChangedEvent):
        for i in range(event.num_records()):
            s = ""
            start = None
            end = None
            old_value = None
            new_value = None
            affected_obj = None
            date_str = f"{dt.datetime.now()}: "
            event_type = 0

            docr = event.get_change_record(i)
            if isinstance(docr, ProgramChangeRecord):
                record = docr
                try:
                    start = str(record.start)
                    end = str(record.end)
                    old_value = str(record.old_value)
                    new_value = str(record.new_value)
                    affected_obj = str(record.object)
                except Exception as e:
                    s += f"{date_str}*** Event data is not available ***\n"
            elif isinstance(docr, CodeUnitPropertyChangeRecord):
                record = docr
                s = f"{date_str}{self.get_event_name(event_type)} ({event_type}) ==> property name={record.property_name}, code unit address={record.address}, old value={record.old_value}, new value={record.new_value}\n"
            else:
                s = self.get_event_name(event_type, DomainObject)
                if s is not None:
                    s += f"{date_str}DomainObject Event ({event_type}): {s}\n"

            if s == "":
                s = f"{date_str}{self.get_event_name(event_type)} ({event_type}) => start param={start}, end param={end}\n" + self.pad_string + "old value=" + old_value + ", new value=" + new_value + ", affected object=" + affected_obj + ", (source={" + event.source + "}\n"

            if s:
                self.provider.display_event(s)

    def get_event_name(self, event_type: int) -> str:
        name = self.event_ht.get(event_type)
        if name is not None:
            return name
        name = self.get_event_name(event_type, DomainObject)
        if name is None:
            # could be from the DomainObject class...
            name = self.get_event_name(event_type, DomainObject)
        self.event_ht[event_type] = name
        return name

    def get_event_name(self, event_type: int, c) -> str:
        fields = c.__dict__.values()
        for field in fields:
            try:
                value = getattr(field, 'value')
                if event_type == value:
                    return f"{field.name}"
            except AttributeError as e:
                # ignore
                pass

    def __str__(self):
        return "DomainEventDisplayPlugin"
```

Note that Python does not have direct equivalent of Java's `@Override` annotation. Also, the code is translated to use Python's built-in data structures and classes instead of those from Java.