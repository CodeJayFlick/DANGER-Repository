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
