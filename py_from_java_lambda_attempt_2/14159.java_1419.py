Here is the translation of the given Java code into Python:

```Python
class DomainEventProcessor:
    def __init__(self):
        self.processor_journal = {}

    def process(self, domain_event: dict) -> None:
        if 'process' in domain_event:
            domain_event['process']()
        self.processor_journal[domain_event.get('id')] = domain_event

    def reset(self) -> None:
        self.processor_journal.clear()

    def recover(self) -> None:
        for event_id, event_data in list(self.processor_journal.items()):
            if 'process' in event_data:
                event_data['process']()
```

Please note that Python does not have direct equivalent of Java's `JsonFileJournal` class. In this translation, I used a dictionary to simulate the journal functionality. Each domain event is stored with its unique id as key and the event data as value.

Also, in Python, we don't need to specify types for function parameters or return values like we do in Java. The type hints are optional and can be removed if not needed.