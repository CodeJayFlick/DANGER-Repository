class EffMessage:
    def __init__(self):
        self.messages = None
        self.message_expr = None
        self.recipients = None
        self.sender = None

    @property
    def SUPPORTS_SENDER(self):
        return hasattr(org.bukkit.command, 'CommandSender') and hasattr(org.bukkit.command.CommandSender, 'sendMessage')

    def init(self, exprs, matched_pattern, is_delayed, parser):
        if not isinstance(exprs[0], list) or len(exprs[0]) == 1:
            self.message_expr = exprs[0]
        else:
            self.messages = [expr for expr in exprs[0]]
        self.recipients = exprs[1]

        if self.SUPPORTS_SENDER and isinstance(exprs[2], org.bukkit.entity.Player):
            self.sender = exprs[2]
        return True

    def execute(self, e):
        sender = None
        command_senders = []

        for receiver in self.recipients.get_array(e):
            if isinstance(receiver, org.bukkit.entity.Player) and any(isinstance(message, str) for message in self.messages):
                components = [ChatMessages.from_parsed_string(toString(message)) for message in self.messages]
            else:
                components = []
                for message in self.messages:
                    array = None
                    if isinstance(message, list):
                        array = message
                    elif not isinstance(message, str):
                        array = ChatMessages.parse(str(message))
                    if receiver instanceof org.bukkit.command.CommandSender and array is not None:
                        receiver.sendMessage(toString(array[0]))
            for command_sender in command_senders:
                if sender is not None:
                    command_sender.spigot().sendMessage(sender.get_unique_id(), *components)
                else:
                    command_sender.spigot().sendMessage(*components)

    def sendMessage(self, receiver, sender=None):
        if self.SUPPORTS_SENDER and sender is not None:
            receiver.spigot().sendMessage(sender.get_unique_id())
        else:
            receiver.spigot().sendMessage()

    def toString(self, e, debug=False):
        return f"send {self.message_expr} to {self.recipients} {' from ' + str(self.sender) if self.sender is not None else ''}"

def toString(obj):
    if isinstance(obj, str):
        return obj
    elif hasattr(org.bukkit.Bukkit, 'toString'):
        return org.bukkit.Bukkit.toString(obj)
