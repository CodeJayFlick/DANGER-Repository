Here is the translation of the given Java code into Python:

```Python
class ExprCmdCooldownInfo:
    def __init__(self):
        self.pattern = None

    @staticmethod
    def register_expression():
        Skript.register_expression(ExprCmdCooldownInfo, Object, ExpressionType.SIMPLE,
                                  ["[the] remaining [time] of [the] (cooldown|wait) [(of|for) the current command]",
                                   "[the] elapsed [time] of [the] (cooldown|wait) [(of|for) the current command]",
                                   "[the] ((cooldown|wait) time|[wait] time of [the] (cooldown|wait) [(of|for) the current command])",
                                   "[the] last usage date of [the] (cooldown|wait) [(of|for) the current command]",
                                   "[the] cooldown bypass permission of [the] (cooldown|wait) [(of|for) the current command]")

    def init(self, exprs: list[Expression], matched_pattern: int, is_delayed: Kleenean, parse_result: ParseResult):
        self.pattern = matched_pattern
        if not get_parser().is_current_event(ScriptCommandEvent()):
            Skript.error("The " + self.get_expression_name() + " expression can only be used within a command", ErrorQuality.SEMANTIC_ERROR)
            return False

    def get(self, event: Event):
        if not isinstance(event, ScriptCommandEvent):
            return None
        script_command = (ScriptCommandEvent)(event).get_skript_command()
        sender = event.get_sender()

        if script_command.get_cooldown() is None or not isinstance(sender, Player):
            return None

        player = (Player)(sender)
        uuid = player.get_unique_id()

        switch self.pattern:
            case 0 | 1:
                ms = pattern != 1 and script_command.get_remaining_milliseconds(uuid, event) or script_command.get_elapsed_milliseconds(uuid, event)
                return [Timespan(ms)]

            case 2:
                return [script_command.get_cooldown()]

            case 3:
                return [script_command.get_last_usage(uuid, event)]

            case 4:
                return [script_command.get_cooldown_bypass()]
        return None

    def accept_change(self, mode: Changer.ChangeMode):
        switch mode:
            case ADD | REMOVE:
                if self.pattern <= 1:
                    return [Timespan]

            case RESET | SET:
                if self.pattern <= 1:
                    return [Timespan]
                elif self.pattern == 3:
                    return [Date]
        return None

    def change(self, event: Event, delta: list[Object], mode: Changer.ChangeMode):
        if not isinstance(event, ScriptCommandEvent):
            return
        script_command = (ScriptCommandEvent)(event).get_skript_command()
        cooldown = script_command.get_cooldown()

        sender = event.get_sender()
        if cooldown is None or not isinstance(sender, Player):
            return

        cooldown_ms = cooldown.get_milliseconds()
        uuid = ((Player)(sender)).get_unique_id()

        switch self.pattern:
            case 0 | 1:
                timespan = delta[0] if delta else Timespan(0)
                switch mode:
                    case ADD | REMOVE:
                        change = (mode == Changer.ChangeMode.ADD) - 1 or script_command.get_remaining_milliseconds(uuid, event) + timespan.get_milliseconds()
                        if self.pattern == 0:
                            remaining = script_command.get_remaining_milliseconds(uuid, event)
                            changed = remaining + change
                            if changed < 0:
                                changed = 0
                            script_command.set_remaining_milliseconds(uuid, event, changed)

                        else:
                            elapsed = script_command.get_elapsed_milliseconds(uuid, event) + timespan.get_milliseconds()
                            if elapsed > cooldown_ms:
                                elapsed = cooldown_ms

                            script_command.set_elapsed_milliseconds(uuid, event, elapsed)
                    case RESET:
                        if self.pattern == 0:
                            script_command.set_remaining_milliseconds(uuid, event, cooldown_ms)

                        else:
                            script_command.set_elapsed_milliseconds(uuid, event, 0)
                    case SET:
                        if self.pattern == 0:
                            script_command.set_remaining_milliseconds(uuid, event, timespan.get_milliseconds())

                        else:
                            script_command.set_elapsed_milliseconds(uuid, event, timespan.get_milliseconds())
                break
            case 3:
                switch mode:
                    case REMOVE_ALL | RESET:
                        script_command.set_last_usage(uuid, event, None)
                        break

                    case SET:
                        date = delta[0] if delta else None
                        script_command.set_last_usage(uuid, event, date)

        return

    def is_single(self):
        return True

    def get_return_type(self):
        if self.pattern <= 2:
            return Timespan
        elif self.pattern == 3:
            return Date
        else:
            return str

    def __str__(self, event: Event = None, debug=False) -> str:
        return f"the {self.get_expression_name()} of the cooldown"

    @property
    def expression_name(self):
        switch self.pattern:
            case 0:
                return "remaining time"
            case 1:
                return "elapsed time"
            case 2:
                return "cooldown time"
            case 3:
                return "last usage date"
            case 4:
                return "bypass permission"

    def __init_subclass__(cls):
        ExprCmdCooldownInfo.register_expression()
```

Please note that Python does not support switch-case statements like Java. Instead, you can use if-elif-else or dictionary-based approaches to achieve similar functionality.