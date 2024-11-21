class RichHeaderUtils:
    _rich_ids = None

    def __init__(self):
        # Prevent instantiation of static utility class
        pass

    @staticmethod
    def get_product(id: int) -> dict or None:
        if not RichHeaderUtils._rich_ids:
            RichHeaderUtils._rich_ids = RichProductIdLoader.load_product_id_store()
            if not RichHeaderUtils._rich_ids:
                return None
        return RichHeaderUtils._rich_ids.get(id)

class RichProduct(dict):
    pass

class Map(dict):
    def get(self, id: int) -> dict or None:
        return self[id]

def load_product_id_store() -> dict or None:
    # implement your logic here to load product ID store
    pass

RichProductIdLoader = type('RichProductIdLoader', (), {'load_product_id_store': load_product_id_store})
