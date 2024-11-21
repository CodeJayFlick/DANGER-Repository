import android as android_module
from android.app import Activity
from android.content import Intent, SharedPreferences
from android.graphics import Color
from android.os import Bundle
from android.view import View, LinearLayout, ImageView
from android.widget import AdapterView
from java.util import Timer, TimerTask

class SplashActivity(Activity):
    def __init__(self):
        super(SplashActivity, self).__init__()

    def onCreate(self, savedInstanceState: Bundle) -> None:
        super.onCreate(savedInstanceState)
        self.setContentView(R.layout.splash)
        com.google.firebase.FirebaseApp.initializeApp(self)
        self.initialize(savedInstanceState)

    def initialize(self, savedInstanceState: Bundle) -> None:
        main_body = (LinearLayout) findViewById(R.id.main_body)
        icon_manager = (ImageView) findViewById(R.id.icon_manager)
        NAVIGATION_BAR = getSharedPreferences("NAVIGATION_ BAR", Activity.MODE_PRIVATE)

    def initializeLogic(self) -> None:
        timer_task = TimerTask()
        timer_task.run = lambda: self.start_activity()

        _timer = Timer()
        _timer.schedule(timer_task, 1000)
        self._dark_navigation()

    def start_activity(self):
        switch_to_main_activity = Intent(self.getApplicationContext(), MainActivity.class)
        self.startActivity(switch_to_main_activity)
        self.finish()

    def _hide_navigation(self) -> None:
        try:
            if NAVIGATION_BAR.getString("NAVIGATION", "").equals("1"):
                window().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_HIDE_NAVIGATION | View.SYSTEM_UI_FLAG_IMMERSIVE_STICKY)
            else:
                if NAVIGATION_BAR.getString("NAVIGATION", "").equals("0"):
                    window().getDecorView().setSystemUiVisibility(View.SYSTEM_UI_FLAG_LAYOUT_STABLE)

        except Exception as e:
            pass

    def _dark_navigation(self) -> None:
        try:
            if Build.VERSION.SDK_INT >= 21:
                window().setNavigationBarColor(Color.parseColor("#212121"))
        except Exception as e:
            pass

    @Deprecated
    def show_message(self, s: str):
        toast.makeText(getApplicationContext(), s, Toast.LENGTH_SHORT).show()

    @Deprecated
    def get_location_x(self, v: View) -> int:
        location = [0]
        v.getLocationInWindow(location)
        return location[0]

    @Deprecated
    def get_location_y(self, v: View) -> int:
        location = [0]
        v.getLocationInWindow(location)
        return location[1]

    @Deprecated
    def get_random(self, min: int, max: int) -> int:
        random = Random()
        return random.randint(min, max)

    @Deprecated
    def get_checked_item_positions_to_array(self, list_view: AdapterView) -> ArrayList:
        result = []
        arr = list_view.getCheckedItemPositions()
        for i in range(arr.size()):
            if arr.valueAt(i):
                result.append(arr.keyAt(i))
        return result

    @Deprecated
    def get_dip(self, input: int) -> float:
        return TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, input, self.getResources().getDisplayMetrics())

    @Deprecated
    def get_display_width_pixels(self) -> int:
        return self.getResources().getDisplayMetrics().widthPixels

    @Deprecated
    def get_display_height_pixels(self) -> int:
        return self.getResources().getDisplayMetrics().heightPixels
