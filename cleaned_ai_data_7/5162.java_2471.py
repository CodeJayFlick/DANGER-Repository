class RichTableRecordDataType:
    def __init__(self, record):
        self.record = record

    @property
    def category_path(self):
        return "/PE"

    @property
    def mnemonic(self):
        return "MSRichRecord"

    @property
    def description(self):
        return "MS Rich Table Record"

    @property
    def length(self):
        return 8

    def has_language_dependent_length(self):
        return False

    def clone(self, dtm):
        if dtm == self.get_data_type_manager():
            return self
        return RichTableRecordDataType(dtm, self.record)

    def get_mnemonic(self, settings):
        return "MSRichRecord"

    def get_representation(self, buf, settings, length):
        return ""

    def copy(self, dtm):
        return self.clone(dtm)

    def initialize(self):
        product_info = MSProductInfoDataType(self.record.get_comp_id())
        object_count = RichObjectCountDataType(self.record.get_object_count())

        self.add(product_info, 4, "productInfo", None)
        self.add(object_count, 4, "objectCount", None)


class MSProductInfoDataType:
    def __init__(self, comp_id):
        self.comp_id = comp_id


class RichObjectCountDataType:
    def __init__(self, object_count):
        self.object_count = object_count
