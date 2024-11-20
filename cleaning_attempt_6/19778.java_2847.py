class Effect:
    def __init__(self):
        pass

    def execute(self, e):
        raise NotImplementedError("Subclasses must implement this method")

    def run(self, e):
        self.execute(e)
        return True


def parse(s: str, default_error=None) -> 'Effect':
    try:
        section = EffectSection.parse(s, None, None, None)
        if section is not None:
            return EffectSectionEffect(section)

        log = SkriptLogger.start_parse_log_handler()
        f = EffFunctionCall.parse(s)
        if f is not None:
            log.print_log()
            return f
        elif log.has_error():
            log.print_error()
            return None
        else:
            log.print_error()

    finally:
        log.stop()

    return SkriptParser.parse(s, iter(Skript.get_effects()), default_error)
