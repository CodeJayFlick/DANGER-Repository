Here is the translation of the given Java code into equivalent Python:

```Python
class MDBasicName:
    def __init__(self):
        self.special_name = None
        self.template_name_and_arguments = None
        self.reusable_name = None
        self.embedded_object = None
        self.name_modifier = ""

    def set_special_name(self, special_name):
        self.special_name = special_name

    def set_template_name_and_arguments(self, template_name_and_arguments):
        self.template_name_and_arguments = template_name_and_arguments

    def set_reusable_name(self, reusable_name):
        self.reusable_name = reusable_name

    def set_embedded_object(self, embedded_object):
        self.embedded_object = embedded_object

    def is_constructor(self):
        if self.special_name:
            return self.special_name.is_constructor()
        elif self.template_name_and_arguments:
            return self.template_name_and_arguments.is_constructor()
        else:
            return False

    def is_destructor(self):
        if self.special_name:
            return self.special_name.is_destructor()
        elif self.template_name_and_arguments:
            return self.template_name_and_arguments.is_destructor()
        else:
            return False

    def is_type_cast(self):
        if self.special_name:
            return self.special_name.is_type_cast()
        elif self.template_name_and_arguments:
            return self.template_name_and_arguments.is_type_cast()
        else:
            return False

    def get_rtti_number(self):
        if self.special_name:
            return self.special_name.get_rtti_number()
        else:
            return -1

    def is_string(self):
        if self.special_name:
            return self.special_name.is_string()
        else:
            return False

    def get_mdstring(self):
        if self.special_name and self.special_name.is_string():
            return self.special_name.get_mdstring()
        else:
            return None

    def get_name(self):
        if self.special_name:
            return self.special_name.name
        elif self.template_name_and_arguments:
            return self.template_name_and_arguments.name
        elif self.reusable_name:
            return self.reusable_name.name
        else:
            return ""

    def set_name_modifier(self, name_modifier):
        self.name_modifier = name_modifier

    def get_embedded_object(self):
        return self.embedded_object

    def insert(self, builder):
        if self.reusable_name:
            self.reusable_name.insert(builder)
        elif self.special_name:
            self.special_name.insert(builder)
        elif self.embedded_object:
            self.embedded_object.insert(builder)
        else:
            self.template_name_and_arguments.insert(builder)

        if self.name_modifier:
            builder.append(self.name_modifier)

    def parse_internal(self):
        # First pass can only have name fragment of special name
        if dmang.peek() == '?':
            if dmang.peek(1) == '$':
                template_name_and_arguments = MDTemplateNameAndArguments(dmang)
                template_name_and_arguments.parse()
            elif dmang.peek(1) == '?':
                embedded_object = MDObjectCPP(dmang)
                embedded_object.parse()
                embedded_object_qualification = MDQualification(dmang)
                embedded_object_qualification.parse()  # Value not used, but must be parsed.
            else:
                dmang.increment()
                special_name = MDSpecialName(dmang, 1)
                special_name.parse()

        else:
            reusable_name = MDReusableName(dmang)
            reusable_name.parse()


class MDTemplateNameAndArguments:
    def __init__(self):
        pass

    # Add methods here


class MDObjectCPP:
    def __init__(self):
        pass

    # Add methods here


class MDSpecialName:
    def __init__(self, dmang, i):
        self.dmang = dmang
        self.i = i

    # Add methods here


class MDReusableName:
    def __init__(self):
        pass

    # Add methods here


class MDQualification:
    def __init__(self):
        pass

    # Add methods here


# Example usage:

dmang = ...  # Initialize dmang
basic_name = MDBasicName()
basic_name.set_special_name(MDSpecialName(dmang, 1))
basic_name.insert(builder)
```

Please note that the Python code above is not a direct translation of the Java code. It's more like an equivalent implementation in Python. The `MDTemplateNameAndArguments`, `MDObjectCPP`, `MDSpecialName`, `MDReusableName`, and `MDQualification` classes are not fully implemented here, as their methods were not provided in the original Java code. You would need to implement these classes based on your specific requirements.

Also note that Python does not have direct equivalents of some Java features like packages, interfaces, or abstract classes. The above implementation is a straightforward translation into equivalent Python constructs.