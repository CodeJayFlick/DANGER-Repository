class WrappedCustomOption:
    def __init__(self):
        self.value = None

    def read_state(self, save_state):
        custom_option_class_name = save_state.get("CUSTOM OPTION CLASS", None)
        try:
            value.__dict__.update(save_state)  # equivalent to value.readState(save_state)
        except Exception as e:
            print(f"Can't create customOption instance for: {custom_option_class_name}", file=sys.stderr)

    def write_state(self, save_state):
        save_state["CUSTOM OPTION CLASS"] = self.value.__class__.__name__
        self.value.write_state(save_state)  # equivalent to value.writeState(save_state)

    @property
    def object(self):
        return self.value

    @property
    def option_type(self):
        return "CUSTOM_ TYPE"  # equivalent to OptionType.CUSTOM_TYPE in Java
