class TocItemProvider:
    def __init__(self):
        pass

    def get_external_toc_items_by_id(self) -> dict:
        """Returns all external TOC items referenced by this provider"""
        return {}

    def get_toc_definitions_by_id(self) -> dict:
        """Returns all TOC items defined by this provider"""
        return {}
