class NavigatableActionContext:
    def __init__(self, provider: object, navigatable: 'Navigatable', program=None, location=None, selection=None, highlight=None):
        super().__init__(provider=provider, program=navigatable.get_program() if program is None else program,
                         location=navigatable.get_location() if location is None else location,
                         selection=navigatable.get_selection() if selection is None else selection,
                         highlight=navigatable.get_highlight() if highlight is None else highlight)
        self.navigatable = navigatable

    @property
    def navigatable(self):
        return self._navigatable

# Note: In Python, we don't need to define a separate constructor for each combination of parameters.
