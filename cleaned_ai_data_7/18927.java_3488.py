class OtherEntity:
    def __init__(self, foo: str):
        self.foo = foo

    @classmethod
    def from_json(cls, json_data):
        return cls(json_data['foo'])

# Note that there's no direct equivalent to Java's `@JsonCreator` and `@JsonProperty`
# annotations in Python. The above code uses a class method named `from_json` 
# which is called when the object is created with JSON data.
