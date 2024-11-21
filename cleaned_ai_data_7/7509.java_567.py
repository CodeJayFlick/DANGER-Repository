class DummyListingFGVertex:
    def __init__(self, controller, address_set_view, flow_type, is_entry):
        super().__init__(controller, address_set_view, flow_type, is_entry)

    def __str__(self):
        return f"Dummy {super().__str__()}"


def equals(self, obj):
    return self == obj
