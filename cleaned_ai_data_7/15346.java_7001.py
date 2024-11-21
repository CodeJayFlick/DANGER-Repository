import toast
from android.widget import Toast
from random import randint
from typing import List, Dict

class SketchwareUtil:
    @staticmethod
    def show_message(context: object, s: str) -> None:
        toast.makeText(context, s, toast.LENGTH_SHORT).show()

    @staticmethod
    def get_location_x(view: object) -> int:
        location = [0, 0]
        view.getLocationInWindow(location)
        return location[0]

    @staticmethod
    def get_location_y(view: object) -> int:
        location = [0, 0]
        view.getLocationInWindow(location)
        return location[1]

    @staticmethod
    def get_random(min_value: int, max_value: int) -> int:
        return randint(min_value, max_value)

    @staticmethod
    def get_checked_item_positions_to_array(list_view: object) -> List[float]:
        result = []
        checked_items = list_view.getCheckedItemPositions()
        for i in range(checked_items.size()):
            if checked_items.valueAt(i):
                result.append(float(checked_items.keyAt(i)))
        return result

    @staticmethod
    def get_dip(context: object, input_value: int) -> float:
        display_metrics = context.getResources().getDisplayMetrics()
        return TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, input_value, display_metrics)

    @staticmethod
    def get_display_width_pixels(context: object) -> int:
        return context.getResources().getDisplayMetrics().widthPixels

    @staticmethod
    def get_display_height_pixels(context: object) -> int:
        return context.getResources().getDisplayMetrics().heightPixels

    @staticmethod
    def get_all_keys_from_map(map: Dict[str, object], output_list: List[str]) -> None:
        if not output_list:
            return
        output_list.clear()

        if map is None or len(map) <= 0:
            return

        for entry in map.values():
            output_list.append(entry)
