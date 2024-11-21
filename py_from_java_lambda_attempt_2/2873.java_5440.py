Here is the translation of the Java code into Python:

```Python
class AutoOptionsTest:
    OPT1_NAME = "Test Option 1"
    OPT1_DEFAULT = 6
    OPT1_DESC = "A test option"
    OPT1_NEW_VALUE = 10

    OPT2_CATEGORY = "Testing"
    OPT2_NAME = "Test Option 2"
    OPT2_DEFAULT = "Default value"
    OPT2_DESC = "Another test option"

    class AnnotatedWithOptionsPlugin:
        def __init__(self, tool):
            self.my_int_option = OPT1_DEFAULT
            self.auto_options_wiring = AutoOptions.wire_options(self)

    class AnnotatedWithOptionsNoParamPlugin(AnnotatedWithOptionsPlugin):
        def update_my_int_option_no_param(self):
            self.update_no_param_count += 1

    class AnnotatedWithOptionsNewOnlyParamDefaultPlugin(AnnotatedWithOptionsPlugin):
        def __init__(self, tool):
            super().__init__(tool)
            self.update_new_only_param_default_new = None
            self.auto_options_wiring = AutoOptions.wire_options(self)

        def update_my_int_option_new_only_param_default(self, new_val):
            self.update_new_only_param_default_new = new_val

    class AnnotatedWithOptionsNewOnlyParamAnnotatedPlugin(AnnotatedWithOptionsPlugin):
        def __init__(self, tool):
            super().__init__(tool)
            self.auto_options_wiring = AutoOptions.wire_options(self)

        def update_my_int_option_new_only_param_annotated(self, new_val):
            self.update_new_only_param_annotated_new = new_val

    class AnnotatedWithOptionsOldOnlyParamAnnotatedPlugin(AnnotatedWithOptionsPlugin):
        def __init__(self, tool):
            super().__init__(tool)
            self.auto_options_wiring = AutoOptions.wire_options(self)

        def update_my_int_option_old_only_param_annotated(self, old_val):
            self.update_old_only_param_annotated_old = old_val

    class AnnotatedWithOptionsNewOldParamDefaultPlugin(AnnotatedWithOptionsPlugin):
        def __init__(self, tool):
            super().__init__(tool)
            self.auto_options_wiring = AutoOptions.wire_options(self)

        def update_my_int_option_new_old_param_default(self, new_val, old_val):
            self.update_new_old_param_default_new = new_val
            self.update_new_old_param_default_old = old_val

    class AnnotatedWithOptionsNewOldParamNewAnnotPlugin(AnnotatedWithOptionsPlugin):
        def __init__(self, tool):
            super().__init__(tool)
            self.auto_options_wiring = AutoOptions.wire_options(self)

        def update_my_int_option_new_old_param_new_annot(self, new_val, old_val):
            self.update_new_old_param_new_anot_new = new_val
            self.update_new_old_param_new_anot_old = old_val

    class AnnotatedWithOptionsNewOldParamOldAnnotPlugin(AnnotatedWithOptionsPlugin):
        def __init__(self, tool):
            super().__init__(tool)
            self.auto_options_wiring = AutoOptions.wire_options(self)

        def update_my_int_option_new_old_param_old_anot(self, new_val, old_val):
            self.update_new_old_param_old_anot_new = new_val
            self.update_new_old_param_old_anot_old = old_val

    class AnnotatedWithOptionsNewOldParamOldNewAnnotPlugin(AnnotatedWithOptionsPlugin):
        def __init__(self, tool):
            super().__init__(tool)
            self.auto_options_wiring = AutoOptions.wire_options(self)

        def update_my_int_option_new_old_param_old_new_anot(self, new_val, old_val):
            self.update_new_old_param_old_new_anot_new = new_val
            self.update_new_old_param_old_new_anot_old = old_val

    class AnnotatedConsumerOnlyPlugin:
        def __init__(self, tool):
            self.others_int_option = None
            self.auto_options_wiring = AutoOptions.wire_options(self)

        def update_my_int_option(self, new_val, old_val):
            self.new_val = new_val
            self.old_val = old_val

    @classmethod
    def setUp(cls):
        cls.env = TestEnv()
        cls.tool = cls.env.get_tool()

    @classmethod
    def tearDown(cls):
        cls.env.dispose()

    @classmethod
    def test_options_registered(cls):
        add_plugin(cls.tool, AnnotatedWithOptionsPlugin)
        options = cls.tool.get_options(MiscellaneousPluginPackage.NAME)
        assert len(options.get_option_names()) == 1
        opt1 = options.get_option(OPT1_NAME, None, None)
        assert opt1.get_default_value() == OPT1_DEFAULT
        assert opt1.get_value(None) == OPT1_DEFAULT
        assert opt1.get_description() == OPT1_DESC

    @classmethod
    def test_options_registered_explicit_category(cls):
        add_plugin(cls.tool, AnnotatedWithOptionsPlugin)
        options = cls.tool.get_options(OPT2_CATEGORY)
        assert len(options.get_option_names()) == 1
        opt2 = options.get_option(OPT2_NAME, None, None)
        assert opt2.get_option_type() == OptionType.STRING

    @classmethod
    def test_options_updated(cls):
        plugin = add_plugin(cls.tool, AnnotatedWithOptionsPlugin)
        options = cls.tool.get_options(MiscellaneousPluginPackage.NAME)
        assert plugin.my_int_option == OPT1_DEFAULT
        options.set_int(OPT1_NAME, OPT1_NEW_VALUE)
        assert plugin.my_int_option == OPT1_NEW_VALUE

    # ... (rest of the test methods)

def add_plugin(tool, plugin_class):
    return tool.get_plugins().add(plugin_class())

class TestEnv:
    def get_tool(self):
        pass

    def dispose(self):
        pass
```

Please note that Python does not have direct equivalent to Java's `@PluginInfo` and other annotations.