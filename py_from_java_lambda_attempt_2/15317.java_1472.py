Here is a translation of the Java code into equivalent Python:

```Python
import toast
from android.graphics import Rect
from android.text import TextUtils
from android.view import Gravity, View
from android.widget import Toast

class CheatSheet:
    ESTIMATED_TOAST_HEIGHT_DIPS = 48

    def setup(view):
        view.set_on_long_click_listener(lambda v: show_cheat_sheet(v, view.get_content_description()))

    def setup(view, text_res_id):
        view.set_on_long_click_listener(lambda v: show_cheet_sheet(v, v.getContext().getString(text_res_id)))

    def setup(view, text):
        view.set_on_long_click_listener(lambda v: show_cheet_sheet(v, text))

    def remove(view):
        view.set_on_long_click_listener(None)

    def show_cheat_sheet(view, text):
        if TextUtils.isEmpty(text):
            return False

        screen_pos = [0, 0]
        display_frame = Rect()
        view.getLocationOnScreen(screen_pos)
        view.getWindowVisibleDisplayFrame(display_frame)

        context = view.getContext()
        view_width = view.getWidth()
        view_height = view.getHeight()
        view_center_x = screen_pos[0] + view_width / 2
        screen_width = context.getResources().getDisplayMetrics().widthPixels
        estimated_toast_height = int(ESTIMATED_TOAST_HEIGHT_DIPS * context.getResources().getDisplayMetrics().density)

        cheat_sheet = Toast.makeText(context, text, toast.LENGTH_SHORT)
        show_below = screen_pos[1] < estimated_toast_height

        if show_below:
            # Show below
            # Offsets are after decorations (e.g. status bar) are factored in
            cheat_sheet.setGravity(Gravity.TOP | Gravity.CENTER_HORIZONTAL, view_center_x - screen_width / 2,
                                   screen_pos[1] - display_frame.top + view_height)
        else:
            # Show above
            # Offsets are after decorations (e.g. status bar) are factored in
            # NOTE: We can't use Gravity.BOTTOM because when the keyboard is up its height isn't factored in.
            cheat_sheet.setGravity(Gravity.TOP | Gravity.CENTER_HORIZONTAL, view_center_x - screen_width / 2,
                                   screen_pos[1] - display_frame.top - estimated_toast_height)

        cheat_sheet.show()
        return True
```

Please note that this code won't run directly as it's a translation of Java to Python. You would need to modify the Android-specific parts (like Toast, View, etc.) according to your Python-Android setup or framework you're using.