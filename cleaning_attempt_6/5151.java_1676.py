class CompId:
    def __init__(self, id):
        self.id = id
        self.product_id = id >> 16
        self.build_number = id & 0x0000FFFF

    @property
    def value(self):
        return self.id

    @property
    def product_id(self):
        return self.product_id

    def get_product_description(self):
        prod = RichHeaderUtils.get_product(self.product_id)
        if prod is None:
            prod_version = f"Unknown Product ({hex(self.product_id)})"
        else:
            prod_version = prod.product_version
        prod_type = prod.product_type if prod is not None else MSProductType.Unknown

        sb = StringBuilder()
        if prod_type != MSProductType.Unknown:
            sb.append(str(prod_type)) + " from " + prod_version
        else:
            sb.append(prod_version)
        return str(sb)

    @property
    def build_number(self):
        return self.build_number

    def __str__(self):
        return f"{self.get_product_description()}, build {self.build_number}"

class MSProductType:
    Unknown = 0
