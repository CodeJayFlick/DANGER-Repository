import ghidra_app_service as app_service
from ghidra_framework_options import GhidraOptions
from ghidra_program_model_address import AddressSet
from ghidra_program_model_block import CodeBlockIterator, BasicBlockModel

class BlockModelScreenShots:
    def __init__(self):
        pass

    @staticmethod
    def test_basic_block_code():
        app_service.close_provider(DataTypesProvider)
        app_service.close_provider(ViewManagerComponentProvider)

        disable_flow_arrows()
        create_minimal_format()
        enlarge_font()

        address_set = AddressSet()
        address_set.add_range(Address(0x004074c6), Address(0x004074fa).subtract(1))

        restrict_view(address_set)
        highlight_code_blocks(address_set)

    @staticmethod
    def disable_flow_arrows():
        code_browser_plugin = app_service.get_plugin(tool, CodeBrowserPlugin)
        listing_panel = code_browser_plugin.get_listing_panel()

        for margin_provider in list(margin_providers):
            listing_panel.remove_margin_provider(margin_provider)

    @staticmethod
    def create_minimal_format():
        code_browser_plugin = app_service.get_plugin(tool, CodeBrowserPlugin)
        listing_panel = code_browser_plugin.get_listing_panel()
        new_format_manager = create_format()

        run_swing(lambda: listing_panel.set_format_manager(new_format_manager))

        return listing_panel

    @staticmethod
    def enlarge_font():
        options = tool.get_options(GhidraOptions.CATEGORY_BROWSER_DISPLAY)
        font = options.get_font(GhidraOptions.OPTION_BASE_FONT, None)

        run_swing(lambda: options.set_font(GhidraOptions.OPTION_BASE_FONT, font.derive_font(18)))

    @staticmethod
    def highlight_code_blocks(address_set):
        program.start_transaction("Test")

        colorizer = tool.get_service(ColorizingService)
        c1 = Color(0xE8F2FE)

        basic_block_model = BasicBlockModel(program)
        code_block_iterator = basic_block_model.get_code_blocks_containing(address_set, TaskMonitorAdapter.DUMMY_MONITOR)

        while code_block_iterator.has_next():
            block = code_block_iterator.next()
            min_address = block.min_address
            max_address = block.max_address

            colorizer.set_background_color(min_address, max_address, c1)
            c1 = (c1 == Color(0xE8F2FE)) and Color(170, 204, 245) or c1

        program.end_transaction(True)

    @staticmethod
    def restrict_view(address_set):
        run_swing(lambda: code_browser_plugin.get_listing_panel().set_view(address_set))

    @staticmethod
    def create_format():
        options_service = tool.get_service(OptionsService)
        display_options = options_service.get_options(GhidraOptions.CATEGORY_BROWSER_DISPLAY)

        manager = FormatManager(display_options, None)

        for i in range(manager.num_models):
            format_model = manager.model(i)
            num_rows = format_model.num_rows

            for row in range(num_rows):
                factories = format_model.factorys(row)

                for col in reversed(range(len(factories))):
                    factory = factories[col]

                    if factory.field_name.index("XRef") != -1:
                        format_model.remove_factory(row, col)
                    elif factory.field_name == EolCommentFieldFactory.FIELD_NAME:
                        format_model.remove_factory(row, col)
                    elif factory.field_name == AddressFieldFactory.FIELD_NAME:
                        factory.width += 25
                        format_model.update_row(row)

        return manager

    @staticmethod
    def run_swing(func):
        # This function is not implemented in the provided Java code.
        pass

if __name__ == "__main__":
    BlockModelScreenShots().test_basic_block_code()
