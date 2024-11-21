import json

class JSONUtils:
    GSON = None
    GSON_PRETTY = None

    def __init__(self):
        self.GSON = self.build_gson()
        self.GSON_PRETTY = self.build_pretty_gson()

    @classmethod
    def build_gson(cls):
        return cls._build_gson(date_format="yyyy-MM-dd'T'HH:mm:ss.SSS'Z'")

    @classmethod
    def _build_gson(cls, date_format=None):
        gson = json.dumps  # equivalent to GsonBuilder()
        if date_format:
            gson.set_date_format(date_format)
        return gson

    @classmethod
    def build_pretty_gson(cls):
        return cls._build_gson(date_format="yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", pretty_print=True)

    @staticmethod
    def serialize_double(src, t, ctx):
        v = src.long_value()
        if src == float(v):  # equivalent to Double.valueOf(String.valueOf(v))
            return json.dumps(v)  # equivalent to new JsonPrimitive(v)
        else:
            return json.dumps(src)  # equivalent to new JsonPrimitive(src)

    @classmethod
    def register_type_adapter(cls, double_class):
        cls._register_type_adapter(double_class, (JSONUtils.serialize_double))

# usage example
json_utils = JSONUtils()
gson = json_utils.GSON
pretty_gson = json_utils.GSON_PRETTY

