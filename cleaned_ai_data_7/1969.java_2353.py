class GadpClientTargetObject:
    def __init__(self):
        self.delegate = None  # Initialize delegate as None for now

    def get_model(self) -> 'GadpClient':
        pass  # This method should return an instance of GadpClient, but it's not implemented here.

    def get_delegate(self) -> object:
        return self.delegate

    def handle_model_object_event(self, notification):
        if isinstance(notification, dict):  # Assuming EventNotification is a dictionary
            event = notification.get('modelObjectEvent')
            deltas = event.get('elementDelta') + event.get('attributeDelta')
            self.delegate.update_with_deltas(deltas)

    def handle_object_invalidate_event(self, notification):
        if isinstance(notification, dict):  # Assuming EventNotification is a dictionary
            event = notification.get('objectInvalidateEvent')
            reason = event.get('reason')
            self.delegate.invalidate_subtree(self, reason)

    def handle_cache_invalidate_event(self, notification):
        if isinstance(notification, dict):  # Assuming EventNotification is a dictionary
            self.delegate.do_clear_caches()

    def handle_console_output_event(self, notification):
        if isinstance(notification, dict):  # Assuming EventNotification is a dictionary
            event = notification.get('consoleOutputEvent')
            channel_index = event.get('channel')
            all_channels = Channel.values()  # Assuming Channel is an enum or list-like object

            if 0 <= channel_index < len(all_channels):
                self.delegate.get_listeners().fire_console_output(self, all_channels[channel_index], event['data'].to_bytes())
            else:
                Msg.error(self, f"Received output for unknown channel {channel_index}: {event['data']}")
