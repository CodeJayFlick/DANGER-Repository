Here is the translation of the given Java code into Python:

```Python
import math
from decimal import Decimal
from typing import List

class EntropyOverviewColorService:
    def __init__(self):
        self.program = None
        self.chunk_size = 0
        self.chunk_buffer = bytearray()
        self.logtable = []
        self.histogram = [0] * 256
        self.palette = None
        self.entropy_options_manager = None
        self.overview_component = None
        self.legend_dialog = None

    def get_name(self):
        return "Entropy"

    def get_color(self, address: int) -> tuple:
        if not self.program:
            return (0, 0, 0)
        entropy = self.compute_entropy(address)
        return self.palette.get_color(entropy)

    def get_help_location(self):
        return HelpLocation("OverviewColorPlugin", "EntropyOverviewBar")

    def initialize(self, tool: object) -> None:
        self.entropy_options_manager = EntropyOverviewOptionsManager(tool, self)
        self.chunk_size = self.entropy_options_manager.get_chunk_size()
        self.chunk_buffer = bytearray(self.chunk_size)
        self.palette = self.entropy_options_manager.get_palette()

    def set_overview_component(self, component: object) -> None:
        self.overview_component = component

    def get_tooltip_text(self, address: int) -> str:
        if not address:
            return ""
        entropy_scaled = self.compute_entropy(address)
        entropy = (entropy_scaled * 8.0) / 255
        buffer = StringBuilder()
        buffer.append("<b>")
        buffer.append(HTMLUtilities.escape_html(self.get_name()))
        buffer.append("</b>\n")
        buffer.append(" ")
        buffer.append(str.format("{0:.2f}", entropy))
        buffer.append(" ")
        buffer.append(self.get_knot_name(entropy_scaled))
        buffer.append("  &nbsp;&nbsp;&nbsp;")
        buffer.append("(")
        buffer.append(HTMLUtilities.escape_html(self.get_block_name(address)))
        buffer.append(" ")
        buffer.append(str(address))
        buffer.append(")")
        return HTMLUtilities.to_wrapped_html(buffer.toString(), 0)

    def get_knot_name(self, entropy: int) -> str:
        knots = self.palette.get_knots()
        for knot in knots:
            if knot.contains(entropy):
                return knot.name
        return ""

    def get_block_name(self, address: int) -> str:
        block = self.program.memory.block(address)
        if block:
            return block.name
        return ""

    def compute_entropy(self, address: int) -> int:
        if not address:
            return 0
        block = self.program.memory.block(address)
        if not block:
            return 0
        chunk_start_address = self.get_chunk_start_address(block, address)
        try:
            bytes_read = block.get_bytes(chunk_start_address, self.chunk_buffer)
            self.compute_histogram(bytes_read)
            return self.quantize_chunk()
        except MemoryAccessException as e:
            return 0

    def quantize_chunk(self) -> int:
        if not self.logtable:
            self.build_log_table()
        sum = 0.0
        for i in range(256):
            sum += math.pow(2, -self.histogram[i])
        sum *= 255.0 / (math.log(sum) * math.log(2))
        val = int(math.floor(sum))
        if val > 255:
            return 255
        return val

    def compute_histogram(self, byte_count: int) -> None:
        self.histogram.fill(0)
        for i in range(byte_count):
            self.histogram[128 + self.chunk_buffer[i]] += 1

    def get_chunk_start_address(self, block: object, address: int) -> int:
        offset = address - block.start
        chunk = offset // self.chunk_size
        return block.start + (chunk * self.chunk_size)

    def set_program(self, program: object) -> None:
        self.program = program

    def build_log_table(self) -> None:
        logtable = [0.0] * (self.chunk_size + 1)
        chunk_float = self.chunk_size
        for i in range(1, self.chunk_size):
            prob = i / chunk_float
            logtable[i] = -prob * math.log(prob) / math.log(2)
        logtable[0] = 0.0
        logtable[self.chunk_size] = 0.0

    def palette_changed(self) -> None:
        if self.overview_component:
            self.overview_component.refresh_all()
        if self.legend_dialog:
            self.legend_dialog.refresh()

    def get_actions(self) -> List[object]:
        actions = []
        actions.append(AbstractColorOverviewAction("Show Legend", self.get_name(), self.overview_component, self.get_help_location()))
        return actions

    def get_program(self) -> object:
        return self.program
```

Please note that Python does not have direct equivalent of Java's `DecimalFormat` and `Math. floor()`. Also, the code uses some libraries like `html.escape_html()` which are not available in standard Python library.