class AssociationStub:
    def __init__(self, source_address: 'Address', destination_address: 'Address', type: str):
        self.source_address = source_address
        self.destination_address = destination_address
        self.type = type
        self.markup_status = {'status': 'AVAILABLE'}

    def clear_status(self) -> None:
        pass

    def get_destination_address(self) -> 'Address':
        return self.destination_address

    def get_markup_items(self, monitor: str) -> list:
        return []

    def get_markup_status(self) -> dict:
        return self.markup_status

    def get_related_associations(self) -> list:
        return []

    def get_session(self) -> None:
        return None

    def get_source_address(self) -> 'Address':
        return self.source_address

    def get_status(self) -> str:
        return 'AVAILABLE'

    def get_type(self) -> str:
        return self.type

    def get_vote_count(self) -> int:
        return 0

    def has_applied_markup_items(self) -> bool:
        return False

    def set_accepted(self) -> None:
        pass

    def set_markup_status(self, markup_items_status: dict) -> None:
        pass

    def set_rejected(self) -> None:
        pass

    def set_vote_count(self, vote_count: int) -> None:
        pass
