Here is the translation of the Java code into Python:

```Python
class MultiSelectionBlendedLayoutBackgroundColorManager:
    def __init__(self, index: int, selections: list[tuple], background_color: tuple):
        self.index = index
        self.selections = selections
        self.background_color = background_color

    @staticmethod
    def get_layout_color_map(index: int, selections: list[tuple], background_color: tuple) -> 'MultiSelectionBlendedLayoutBackgroundColorManager':
        intersections = [cfs for cfs in selections if cfs[1]]
        empties = [cfs for cfs in intersections if not cfs[0].isTotal()]
        
        if len(empties) == len(intersections):
            return EmptyLayoutBackgroundColorManager(background_color)

        blender = ColorBlender()
        if background_color:
            blender.add(*background_color)
            
        totals = [cfs for cfs in intersections if cfs[0].isTotal()]
        if len(totals) + len(empties) == len(intersections):
            for color in (cfs[1] for cfs in selections if cfs[0].isTotal()):
                blender.add(*color)
            return EmptyLayoutBackgroundColorManager(blender.get_color(background_color))
        
        start_of_line = FieldLocation(index, 0, 0, 0)
        end_of_line = FieldLocation(index, int(1e9), int(1e9), int(1e9))

        for cfs in intersections:
            if cfs[0].contains(start_of_line):
                blender.add(*cfs[1])
        
        return MultiSelectionBlendedLayoutBackgroundColorManager(index, selections, background_color, 
                                                                  blender.get_color(background_color), 
                                                                  ColorBlender().add(*background_color).get_color())

    def get_padding_color(self) -> tuple:
        if self.index == 0:
            return (self.left_border_color,)
        elif self.index == -1:
            return (self.right_border_color,)
        else:
            return self.get_padding_color_between_fields()

    @staticmethod
    def dont_paint_bg(color: tuple):
        return color[0] if len(color) > 1 and color[-1] == MultiSelectionBlendedLayoutBackgroundColorManager.background_color else None

class EmptyLayoutBackgroundColorManager:
    EMPTY_INSTANCE = object()
    
    def __init__(self, background_color: tuple):
        self.background_color = background_color

    @staticmethod
    def get_instance(background_color: tuple) -> 'EmptyLayoutBackgroundColorManager':
        return EmptyLayoutBackgroundColorManager(background_color)

class MultiSelectionBlendedFieldBackgroundColorManager:
    def __init__(self, index: int, field_num: int, layout_selection: object, selections: list[tuple], background_color: tuple):
        self.index = index
        self.field_num = field_num
        self.layout_selection = layout_selection
        self.selections = selections
        self.background_color = background_color

    def get_background_color(self) -> tuple:
        return MultiSelectionBlendedLayoutBackgroundColorManager.dont_paint_bg(self.background_color)

    @staticmethod
    def compute_solid_color(range: 'FieldRange') -> tuple or None:
        blender = ColorBlender()
        
        for cfs in selections:
            if cfs[0].contains_entirely(range):
                blender.add(*cfs[1])
                continue
            
            return None
        
        return blender.get_color(MultiSelectionBlendedLayoutBackgroundColorManager.background_color)

    def get_field_background_color_manager(self, field_num: int) -> object or 'EmptyFieldBackgroundColorManager':
        start = FieldLocation(self.index, field_num - 1, int(1e9), int(1e9))
        end = FieldLocation(self.index, field_num, 0, 0)
        
        range_ = FieldRange(start, end)

        if MultiSelectionBlendedLayoutBackgroundColorManager.excluded_by_all(range_):
            return EmptyFieldBackgroundColorManager.EMPTY_INSTANCE
        
        solid_color = self.compute_solid_color(range_)
        if solid_color:
            return FullySelectedFieldBackgroundColorManager(solid_color)
        
        # Could separate out solid colors, but at the expense of constructing a collection.... 
        # Leave fieldBackgroudColor the same as backgroundColor, and pass all selections in
        return MultiSelectionBlendedFieldBackgroundColorManager(self.index, self.field_num - 1, self.layout_selection, 
                                                                  self.selections, self.background_color)

    def get_background_color(self) -> tuple:
        blender = ColorBlender()
        
        for cfs in self.selections:
            if cfs[0].contains(FieldLocation(self.index, self.field_num, int(1e9), int(1e9))):
                blender.add(*cfs[1])
        
        return blender.get_color()

class EmptyFieldBackgroundColorManager:
    EMPTY_INSTANCE = object()
    
    def __init__(self):
        pass

    @staticmethod
    def get_instance() -> 'EmptyFieldBackgroundColorManager':
        return EmptyFieldBackgroundColorManager()

class FullySelectedFieldBackgroundColorManager:
    def __init__(self, solid_color: tuple):
        self.solid_color = solid_color

    def get_background_color(self) -> tuple:
        return self.solid_color

class FieldLocation:
    def __init__(self, index: int, field_num: int, row: int, col: int):
        self.index = index
        self.field_num = field_num
        self.row = row
        self.col = col

class FieldRange:
    def __init__(self, start: 'FieldLocation', end: 'FieldLocation'):
        self.start = start
        self.end = end

    @staticmethod
    def intersect(range1: object, range2: object) -> tuple or None:
        if not (range1[0].index == range2[0].index and 
                range1[0].field_num <= range2[0].field_num):
            return None
        
        start = FieldLocation(max((range1[0].row, range2[0].row)), max((range1[0].col, range2[0].col)))
        end = FieldLocation(min((range1[0].index, range2[0].index)), min((range1[0].field_num + 1, range2[0].field_num + 1)))

        return (start, end)

    def contains_entirely(self) -> bool:
        pass

class ColorBlender:
    @staticmethod
    def add(*colors: tuple):
        if len(colors) > 1 and colors[-1] == MultiSelectionBlendedLayoutBackgroundColorManager.background_color:
            return None
        
        return (*colors,)

    def get_color(self, background_color: tuple or None = None) -> tuple or None:
        if not self.added_colors:
            return None

        result = list(set(self.added_colors))
        
        for color in result:
            if len(color) > 1 and color[-1] == MultiSelectionBlendedLayoutBackgroundColorManager.background_color:
                return None
        
        return (*result,)

    @property
    def added_colors(self):
        pass

class Highlight:
    def __init__(self, min: int, max: int, color: tuple or None = None):
        self.min = min
        self.max = max
        self.color = color if isinstance(color, tuple) else MultiSelectionBlendedLayoutBackgroundColorManager.background_color

    @property
    def start(self):
        return self.min

    @property
    def end(self):
        return self.max