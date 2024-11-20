class ItemWithCustomModelData:
    def __init__(self):
        self.data = None

    @property
    def name(self):
        return "Item with Custom Model Data"

    @property
    def description(self):
        return "Get an item with a CustomModelData tag. (Value is an integer between 0 and 99999999)"

    @property
    def examples(self):
        return ["give player a diamond sword with custom model data 2", 
                "set slot 1 of inventory of player to wooden hoe with custom model data 357"]

    @property
    def required_plugins(self):
        return ["1.14+"]

    @property
    def since(self):
        return "2.5"

    def init(self, exprs, i, kleenean, parse_result):
        self.expr = exprs[0]
        self.data = exprs[1]
        return True

    def get(self, e, source):
        data = self.data.get_single(e)
        if data is None:
            return source
        result = [item.clone() for item in source]
        for item in result:
            meta = item.item_meta()
            meta.set_custom_model_data(data.int_value())
            item.set_item_meta(meta)
        return result

    def get_return_type(self):
        return ItemType

    def __str__(self, e=None, debug=False):
        if not isinstance(e, Event) and not isinstance(debug, bool):
            raise TypeError("Invalid type for event or debug parameter")
        return f"{self.expr.__str__(e, debug)} with custom model data {data.__str__(e, debug)}"
