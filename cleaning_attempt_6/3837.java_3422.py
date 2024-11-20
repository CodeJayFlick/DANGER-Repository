class FlowArrowShapeFactory:
    def __init__(self):
        pass  # factory; can't create

    TRIANGLE_HEIGHT = 9
    TRIANGLE_WIDTH = 7

    @staticmethod
    def create_arrow_body(plugin, arrow, width, height, line_spacing):
        line_path = GeneralPath()

        start_top = plugin.get_start_pos(arrow.start)
        start_bottom = plugin.get_end_pos(arrow.start)
        if start_top is not None and start_bottom is not None:
            start_y = (start_top + start_bottom) // 2
        elif plugin.is_below_screen(arrow.start):
            start_y = height

        end_top = plugin.get_start_pos(arrow.end)
        end_bottom = plugin.get_end_pos(arrow.end)
        if end_top is not None and end_bottom is not None:
            end_y = (end_top + end_bottom) // 2
            end_y = min(end_y, height)  # ensure on screen
        elif plugin.is_below_screen(arrow.end):
            end_y = height

        x = width - ((arrow.depth + 1) * line_spacing)
        if x < 3:
            x = 3

        if start_y != 0 and start_y != height:
            line_path.move_to(width, start_y)
            line_path.line_to(x, start_y)

        # the vertical bar
        off_screen = end_y == 0 or end_y == height
        arrow_height = TRIANGLE_HEIGHT - 1 if off_screen else 0
        arrow_height *= -1 if arrow.is_up() else 1
        line_path.move_to(x, start_y)  # top/corner
        line_path.line_to(x, end_y - arrow_height)

        if end_y != 0 and end_y != height:  # completely on screen
            line_path.move_to(x, end_y)
            line_path.line_to(width - TRIANGLE_WIDTH, end_y)

        return line_path

    @staticmethod
    def create_arrow_head(plugin, arrow, width, height, line_spacing):
        addr_start_int = plugin.get_start_pos(arrow.end)
        addr_end_int = plugin.get_end_pos(arrow.end)
        if addr_start_int is not None and addr_end_int is not None:
            end_y = (addr_start_int + addr_end_int) // 2
            end_y = min(end_y, height)  # ensure on screen
        elif plugin.is_below_screen(arrow.end):
            end_y = height

        x = width - ((arrow.depth + 1) * line_spacing)
        if x < 0:
            x = 3

        half_height = TRIANGLE_HEIGHT // 2
        arrow_path = GeneralPath()
        if end_y != 0 and end_y != height:  # completely on screen
            arrow_path.move_to(width, end_y)
            arrow_path.line_to(width - TRIANGLE_WIDTH, end_y - half_height)
            arrow_path.line_to(width - TRIANGLE_WIDTH, end_y + half_height)
            arrow_path.close()
        elif end_y == 0:
            offset = 0
            arrow_path.move_to(x, offset)
            arrow_path.line_to(x - half_height, offset + TRIANGLE_WIDTH)
            arrow_path.line_to(x + half_height, offset + TRIANGLE_WIDTH)
            arrow_path.close()
        else:  # end_y == height
            arrow_path.move_to(x, height)
            arrow_path.line_to(x - half_height, height - TRIANGLE_WIDTH)
            arrow_path.line_to(x + half_height, height - TRIANGLE_WIDTH)
            arrow_path.close()

        return arrow_path

class GeneralPath:
    def move_to(self, x, y):
        pass  # implement this method as needed
