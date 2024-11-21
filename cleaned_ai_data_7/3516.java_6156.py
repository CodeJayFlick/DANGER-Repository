# ###

import ghidra_app_plugin_core_codebrowser_hover as hover

class FunctionSignatureListingHoverPlugin:
    def __init__(self, tool):
        self.function_signature_hover = hover.FunctionSignatureListingHover(tool)
        # register service provided
        pass  # TODO: implement registration in Python equivalent of PluginTool

    @property
    def status(self):
        return "RELEASED"

    @property
    def package_name(self):
        return "CorePluginPackage.NAME"  # assume this is a constant or attribute access

    @property
    def category(self):
        return hover.PluginCategoryNames.CODE_VIEWER

    @property
    def short_description(self):
        return "Shows formatted tool tip text over function signatures"

    @property
    def description(self):
        return f"This plugin extends the functionality of the code browser by adding a tooltip over function signature fields in Listing."

    # services provided (assuming this is equivalent to Java's PluginInfo.servicesProvided)
    @property
    def services_provided(self):
        return [hover.ListingHoverService]

def dispose(self):
    self.function_signature_hover.dispose()

# ###

if __name__ == "__main__":
    tool = ghidra_app_plugin_core_codebrowser_hover.PluginTool()  # assume this is a Python equivalent of Java's PluginTool
    plugin = FunctionSignatureListingHoverPlugin(tool)
