class Section:
    def __init__(self):
        pass

    @abstractmethod
    def init(self, exprs: list[Expression], matched_pattern: int, is_delayed: Kleenean, parse_result: ParseResult) -> bool:
        pass

    def load_code(self, section_node: 'SectionNode') -> None:
        current_sections = self.get_parser().get_current_sections()
        current_sections.append(self)
        try:
            trigger_items = ScriptLoader.load_items(section_node)
            set_trigger_items(trigger_items)
        finally:
            current_sections.remove(current_sections[-1])

    def load_code_with_event_name_and_events(self, section_node: 'SectionNode', name: str, events: list[Class]) -> Trigger:
        parser = self.get_parser()
        previous_name = parser.get_current_event_name()
        previous_events = parser.get_current_events()
        previous_skript_event = parser.get_current_skript_event()
        previous_sections = parser.get_current_sections()
        previous_delay = parser.get_has_delay_before()

        parser.set_current_event(name, events)
        skript_event = SectionSkriptEvent(name, self)
        parser.set_current_skript_event(skript_event)
        parser.set_current_sections([])
        parser.set_has_delay_before(Kleenean.FALSE)

        trigger_items = ScriptLoader.load_items(section_node)

        #noinspection ConstantConditions
        parser.set_current_event(previous_name, previous_events)
        parser.set_current_skript_event(previous_skript_event)
        parser.set_current_sections(previous_sections)
        parser.set_has_delay_before(previous_delay)

        script = parser.get_current_script()
        return Trigger(script if script else None, name, skript_event, trigger_items)

    def load_optional_code(self, section_node: 'SectionNode') -> None:
        had_delay_before = self.get_parser().get_has_delay_before()
        self.load_code(section_node)
        if had_delay_before.is_true():
            return
        if not self.get_parser().get_has_delay_before().is_false():
            self.get_parser().set_has_delay_before(Kleenean.UNKNOWN)

    @staticmethod
    def parse(expr: str, default_error: str = None, section_node: 'SectionNode', trigger_items: list[TriggerItem]) -> 'Section':
        return SkriptParser.parse(expr, [section for section in Skript.get_sections()], default_error)
