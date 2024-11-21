class LoaderArgsOptionChooser:
    def __init__(self, loader_filter):
        self.loader_args = loader_filter.get_loader_args()

    def choose(self, option_choices, address_factory=None):
        if self.loader_args is not None:
            for pair in self.loader_args:
                arg, val = pair
                found_it = False
                for option in option_choices:
                    if option.arg and arg.lower() == option.arg.lower():
                        old_val = option.value
                        try:
                            option.parse_and_set_value(val)
                            print(f"Successfully applied '{arg}' to '{option.name}' (old: {old_val}, new: {val})")
                        except Exception as e:
                            print(f"Failed to apply '{arg}' to '{option.name}' (old: {old_val}, bad: {val})")
                            return None
                        found_it = True
                        break
                if not found_it:
                    print(f"Loader does not support {arg} argument")
                    return None
        return option_choices

# Note that Python doesn't have direct equivalent of Java's Pair class, so I used tuple instead.
