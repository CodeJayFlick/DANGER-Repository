class ObjectAttributeRow:
    def __init__(self, target_object: 'TargetObject', provider):
        self.target_object = target_object

    @property
    def target_object(self):
        return self.target_object

    @property
    def name(self):
        return self.target_object.name

    @property
    def kind(self):
        attributes = self.target_object.cached_attributes
        object_value = attributes.get('kind')
        if object_value is not None:
            return str(object_value)
        return self.target_object.type_hint

    @property
    def value(self):
        attributes = self.target_object.cached_attributes
        object_value = attributes.get('value')
        if object_value is not None:
            return str(object_value)
        return self.target_object.display

    @property
    def display(self):
        value = self.target_object.display
        if ':' in value:
            value = value.split(':')[0]
        return value

    @property
    def type(self):
        attributes = self.target_object.cached_attributes
        object_value = attributes.get('type')
        if object_value is not None:
            return str(object_value)
        return ''
