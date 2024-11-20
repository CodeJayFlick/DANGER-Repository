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
