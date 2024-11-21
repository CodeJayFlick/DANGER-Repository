class VTMATCHCONTEXT:
    def __init__(self, provider, selected_matches, session):
        self.selected_matches = selected_matches
        self.session = session

    @property
    def selected_matches(self):
        return self._selected_matches

    @selected_matches.setter
    def selected_matches(self, value):
        self._selected_matches = value

    @property
    def session(self):
        return self._session

    @session.setter
    def session(self, value):
        self._session = value


class VTMatch:
    pass  # placeholder for the VTMatch class


class VTSession:
    pass  # placeholder for the VTSession class


def main():
    provider = None  # replace with actual implementation
    selected_matches = []  # initialize as empty list
    session = None  # replace with actual implementation

    context = VTMATCHCONTEXT(provider, selected_matches, session)

    print(context.selected_matches)  # prints the selected matches
    print(context.session)  # prints the VTSession object


if __name__ == "__main__":
    main()
