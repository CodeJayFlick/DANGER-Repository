class MarkerDescriptor:
    def __init__(self):
        pass

    def get_program_location(self, loc: 'MarkerLocation') -> 'ProgramLocation':
        return None

    def get_tooltip(self, loc: 'MarkerLocation') -> str:
        return None

    def get_icon(self, loc: 'MarkerLocation') -> 'ImageIcon':
        return None
