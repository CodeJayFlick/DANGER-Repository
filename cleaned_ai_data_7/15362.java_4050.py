import android

class BrightnessControl:
    def __init__(self, activity):
        self.activity = activity
        self.current_brightness_level = -1

    def get_screen_brightness(self):
        return self.activity.window.get_attributes().screen_brightness

    def set_screen_brightness(self, brightness):
        lp = self.activity.window.get_attributes()
        lp.screen_brightness = brightness
        self.activity.window.set_attributes(lp)

    def change_brightness(self, player_view, increase, can_set_auto):
        new_brightness_level = (1 if increase else -1) + self.current_brightness_level

        if can_set_auto and new_brightness_level < 0:
            self.current_brightness_level = -1
        elif 0 <= new_brightness_level <= 30:
            self.current_brightness_level = new_brightness_level

        if self.current_brightness_level == -1 and can_set_auto:
            self.set_screen_brightness(0)
        else:
            brightness_value = self.level_to_brightness(self.current_brightness_level)
            self.set_screen_brightness(brightness_value)

        player_view.set_highlight(False)

        if self.current_brightness_level == -1 and can_set_auto:
            player_view.setIconBrightnessAuto()
            player_view.setCustomErrorMessage("")
        else:
            player_view.setIconBrightness()
            player_view.setCustomErrorMessage(f" {self.current_brightness_level}")

    def level_to_brightness(self, level):
        d = 0.064 + (30 * 0.936) / level
        return round(d ** 2, 1)
