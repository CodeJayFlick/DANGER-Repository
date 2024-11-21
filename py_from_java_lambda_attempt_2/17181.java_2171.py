Here is the translation of the given Java code into Python:

```Python
class TemplateManager:
    def __init__(self):
        self.template_map = {}

    @staticmethod
    def get_instance():
        if not hasattr(TemplateManager, 'instance'):
            TemplateManager.instance = TemplateManager()
        return TemplateManager.instance

    @staticmethod
    def get_new_instance_for_test():
        return TemplateManager()

    def create_schema_template(self, plan):
        for schema_name in plan.schema_names:
            MetaFormatUtils.check_node_name(schema_name)
        for measurements in plan.measurements:
            MetaFormatUtils.check_schema_measurement_names(measurements)

        template = Template(plan)
        if self.template_map.get(plan.name) is not None:
            raise MetadataException("Duplicated template name: " + plan.name)
        else:
            self.template_map[plan.name] = template

    def get_template(self, template_name):
        return self.template_map.get(template_name)

    def check_is_template_and_mnode_compatible(self, template, node):
        if node.schema_template is not None and node.schema_template != template:
            raise MetadataException("Specified node already has a different template")
        for schema_name in template.schema_map.keys():
            if node.has_child(schema_name):
                raise MetadataException(
                    f"Schema name {schema_name} in template conflicts with node's child {node.get_full_path()}.{schema_name}"
                )

    def clear(self):
        self.template_map.clear()


class Template:
    def __init__(self, plan):
        # implement the rest of the class
        pass


class MetadataException(Exception):
    pass


class UndefinedTemplateException(Exception):
    pass


class DuplicatedTemplateException(Exception):
    pass
```

Note that this translation is not a direct conversion from Java to Python. It's more like an interpretation of how you could translate it, considering the differences between both languages and their respective idioms.

In particular:

- The `@TestOnly` annotation in Java doesn't have a direct equivalent in Python.
- In Python, we use dictionaries (`{}`) instead of maps or hashmaps. We also don't need to specify types for dictionary keys like we do with Java's `Map`.
- Exception handling is similar between both languages but the specific exceptions and their hierarchy are different.
- The `IMNode` class doesn't have a direct equivalent in Python, so I left it as-is. You would likely replace this with your own custom node class or use an existing one if you're working with some kind of graph library.

Remember that translating code from Java to Python requires understanding the differences between both languages and their respective idioms.