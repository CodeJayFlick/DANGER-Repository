Here is the translation of the Java code into Python:

```Python
class CompiledAuthorizationRules:
    def __init__(self, config):
        self.config = config
        self.compiled_rules = compile_authorization_rules()

    @staticmethod
    def ALLOW_VIEWING_ALL_REFS_ID():
        return "__ALLOW_VIEWING_REF_ID"

    @staticmethod
    def ALLOW_VIEWING_ALL_REFS():
        return f"op=='{VIEW_REFERENCE}' && ref.matches('.*')"

    def compile_authorization_rules(self):
        rules = {k: v for k, v in self.config.rules().items()}
        
        if not any(VIEW_REFERENCE.name() in rule_value for rule_value in rules.values()):
            rules[self.ALLOW_VIEWING_ALL_REFS_ID()] = self.ALLOW_VIEWING_ALL_REFS()
            
        scripts = {}
        for key, value in rules.items():
            try:
                script = CELUtil.build_script(value)
                script.with_container(CELUtil.CONTAINER).with_declarations(CELUtil.AUTHORIZATION_RULE_DECLARATIONS).build()
                scripts[key] = script
            except ScriptException as e:
                raise RuntimeError(f"Failed to compile authorization rule with id '{key}' and expression '{value}' due to: {e.message}", e)
                
        return ImmutableMap(scripts)

    def get_rules(self):
        return self.compiled_rules

# Assuming VIEW_REFERENCE is a constant defined elsewhere
VIEW_REFERENCE = "view_reference"
```

Please note that this translation assumes the following:

- The `QuarkusNessieAuthorizationConfig` class has been replaced with a Python dictionary or another data structure.
- The `CELUtil` class and its methods have been replaced with equivalent functionality in Python. This may involve using libraries such as Celery, CELScript, etc., depending on what you're trying to achieve.
- The `ImmutableMap` class from Java is not available in Python by default. You can use the built-in dictionary type instead.

This translation also assumes that the constants and variables defined elsewhere are replaced with equivalent functionality or values in Python.