class MemoryTypeProgramLocationBasedTableColumn:
    def __init__(self):
        self.renderer = MemoryTypeRenderer()
        self.comparator = MemoryTypeComparator()

    @property
    def column_name(self):
        return "Mem Type"

    def get_value(self, row_object: ProgramLocation, settings: Settings, program: Program) -> MemoryBlock:
        memory = program.get_memory()
        block = memory.get_block(row_object.get_address())
        return block

    def get_program_location(self, row_object: ProgramLocation, settings: Settings, program: Program) -> ProgramLocation:
        return row_object

    @property
    def column_renderer(self):
        return self.renderer

    @property
    def comparator(self):
        return self.comparator


class MemoryTypeRenderer:
    def __init__(self):
        self.disabled_color = Color(200, 200, 200)
        self.off_icon = ResourceManager.load_image("images/EmptyIcon16.gif")
        self.on_icon = ResourceManager.load_image("images/check.png")

    @property
    def html_rendering_enabled(self):
        return True

    def get_table_cell_renderer_component(self, data: GTableCellRenderingData) -> Component:
        the_renderer = super().get_table_cell_renderer_component(data)
        value = data.get_value()
        if value is None:
            return self

        block = MemoryBlock(value)

        buffy = StringBuffer("<html>")
        tooltip_buffy = StringBuffer("<html>")

        as_string(block, buffy, tooltip_buffy)

        the_renderer.set_text(buffy.toString())
        the_renderer.set_tooltip_text(tooltip_buffy.toString())

        return the_renderer

    def as_string(self, block: MemoryBlock, buffy: StringBuffer, tooltip_buffy: StringBuffer):
        update_for_read(block, buffy, tooltip_buffy)
        update_for_write(block, buffy, tooltip_buffy)
        update_for_execute(block, buffy, tooltip_buffy)

    def update_for_volatile(self, block: MemoryBlock, buffy: StringBuffer, tooltip_buffy: StringBuffer):
        if block.is_volatile():
            buffy.append("<b>V</b>")
            tooltip_buffy.append(f"<image src=\"{self.on_icon.description}\"">")
        else:
            buffy.append(HTMLUtilities.color_string(self.disabled_color, "V"))
            tooltip_buffy.append(f"<image src=\"{self.off_icon.description}\"">")

        tooltip_buffy.append("Volatile<br>")

    def update_for_execute(self, block: MemoryBlock, buffy: StringBuffer, tooltip_buffy: StringBuffer):
        if block.is_execute():
            buffy.append("<b>E</b>")
            tooltip_buffy.append(f"<image src=\"{self.on_icon.description}\"">")
        else:
            buffy.append(HTMLUtilities.color_string(self.disabled_color, "E"))
            tooltip_buffy.append(f"<image src=\"{self.off_icon.description}\"">")

        tooltip_buffy.append("Execute<br>")

    def update_for_write(self, block: MemoryBlock, buffy: StringBuffer, tooltip_buffy: StringBuffer):
        if block.is_write():
            buffy.append("<b>W</b>")
            tooltip_buffy.append(f"<image src=\"{self.on_icon.description}\"">")
        else:
            buffy.append(HTMLUtilities.color_string(self.disabled_color, "W"))
            tooltip_buffy.append(f"<image src=\"{self.off_icon.description}\"">")

        tooltip_buffy.append("Write<br>")

    def update_for_read(self, block: MemoryBlock, buffy: StringBuffer, tooltip_buffy: StringBuffer):
        if block.is_read():
            buffy.append("<b>R</b>")
            tooltip_buffy.append(f"<image src=\"{self.on_icon.description}\"">")
        else:
            buffy.append(HTMLUtilities.color_string(self.disabled_color, "R"))
            tooltip_buffy.append(f"<image src=\"{self.off_icon.description}\"">")

        tooltip_buffy.append("Read<br>")

    def get_filter_string(self, t: MemoryBlock, settings: Settings) -> str:
        if t is None:
            return ""

        buffy = StringBuffer("<html>")
        tooltip_buffy = StringBuffer("<html>")

        as_string(t, buffy, tooltip_buffy)

        return buffy.toString()


class MemoryTypeComparator:
    def compare(self, o1: MemoryBlock, o2: MemoryBlock) -> int:
        return o1.get_permissions() - o2.get_permissions()
