Here is a translation of your Java code into equivalent Python:

```Python
import android.content.Context
from android.view import MotionEvent, View
from androidx.core.view import GestureDetectorCompat
from com.brouken.player.CustomStyledPlayerView import CustomStyledPlayerView
from com.brouken.player.R import R

class DoubleTapPlayerView(CustomStyledPlayerView):
    def __init__(self, context: Context, attrs=None, defStyleAttr=0):
        super().__init__(context, attrs, defStyleAttr)
        
        self.controller_ref = -1
        
        if attrs is not None:
            a = context.obtainStyledAttributes(attrs, R.styleable.DoubleTapPlayerView, 0, 0)
            self.controller_ref = a.getResourceId(R.styleable.DoubleTapPlayerView_dtpv_controller, -1) if a else -1
            if a:
                a.recycle()
        
        is_double_tap_enabled = True
        double_tap_delay = 700
        
    def __init__(self, context: Context):
        self.__init__(context, None)
    
    @property
    def is_double_tap_enabled(self) -> bool:
        return is_double_tap_enabled
    
    @is_double_tap_enabled.setter
    def set_double_tap_enabled(self, value: bool):
        global is_double_tap_enabled
        is_double_tap_enabled = value

    @property
    def double_tap_delay(self) -> int:
        return double_tap_delay
    
    @double_tap_delay.setter
    def set_double_tap_delay(self, value: int):
        gesture_listener.set_double_tap_delay(value)
        global double_tap_delay
        double_tap_delay = value

    def get_controller(self) -> 'PlayerDoubleTapListener':
        return self.gesture_listener.get_controls()

    def set_controller(self, controller: 'PlayerDoubleTapListener'):
        self.gesture_listener.set_controls(controller)
        self.controller = controller
    
    @property
    def is_in_double_tap_mode(self) -> bool:
        return self.gesture_listener.is_double_tapping()
    
    def keep_in_double_tap_mode(self):
        self.gesture_listener.keep_in_double_tap_mode()

    def cancel_in_double_tap_mode(self):
        self.gesture_listener.cancel_in_double_tap_mode()

    @Override
    def on_touch_event(self, event: MotionEvent) -> bool:
        if is_double_tap_enabled:
            consumed = self.gesture_detector.on_touch_event(event)
            
            # Do not trigger original behavior when double tapping
            # otherwise the controller would show/hide - it would flack
            if not consumed:
                return super().on_touch_event(event)

            return True
        
        return super().on_touch_event(event)


class DoubleTapGestureListener(GestureDetector.SimpleOnGestureListener):
    def __init__(self, root_view: CustomStyledPlayerView):
        self.root_view = root_view
        self.m_handler = Handler()
        self.m_runnable = Runnable(self)
        
        self.controls = None
        self.is_double_tapping = False
        self.double_tap_delay = 650

    def is_double_tapping(self) -> bool:
        return self.is_double_tapping
    
    @property
    def double_tap_delay(self):
        return self.double_tap_delay
    
    @double_tap_delay.setter
    def set_double_tap_delay(self, value: int):
        self.double_tap_delay = value

    def get_controls(self) -> 'PlayerDoubleTapListener':
        return self.controls
    
    @property
    def is_double_tapping(self) -> bool:
        return self.is_double_tapping
    
    @is_double_tapping.setter
    def set_double_tapping(self, value: bool):
        self.is_double_tapping = value

    def keep_in_double_tap_mode(self):
        if not self.is_double_tapping:
            self.is_double_tapping = True
            self.m_handler.postDelayed(self.m_runnable, self.double_tap_delay)
        
        if self.controls is not None:
            self.controls.on_double_tap_started(event.x, event.y)

    def cancel_in_double_tap_mode(self):
        self.m_handler.removeCallbacks(self.m_runnable)
        self.is_double_tapping = False
        
        if self.controls is not None:
            self.controls.on_double_tap_finished()

    @Override
    def on_down(self, event: MotionEvent) -> bool:
        if self.is_double_tapping and self.controls is not None:
            self.controls.on_double_tap_progress_down(event.x, event.y)
        
        return True

    @Override
    def on_single_tap_up(self, event: MotionEvent) -> bool:
        if self.is_double_tapping and self.controls is not None:
            self.controls.on_double_tap_progress_up(event.x, event.y)

        return True

    @Override
    def on_single_tap_confirmed(self, event: MotionEvent) -> bool:
        # Ignore this event if double tapping is still active
        # Return true needed because this method is also called if you tap e.g. three times in a row,
        # therefore the controller would appear since the original behavior is to hide and show on single tap
        if self.is_double_tapping:
            return True
        
        if event.get_action_masked() == MotionEvent.ACTION_UP and self.is_double_tapping:
            if self.controls is not None:
                self.controls.on_double_tap_progress_up(event.x, event.y)
        
        #return root_view.perform_click()
        return root_view.tap()

    @Override
    def on_double_tap(self, event: MotionEvent) -> bool:
        if DEBUG:
            print("onDoubleTap")
        
        if not self.is_double_tapping:
            self.is_double_tapping = True
            keep_in_double_tap_mode()
            
            if self.controls is not None:
                self.controls.on_double_tap_started(event.x, event.y)
        
        return True

    @Override
    def on_double_tap_event(self, event: MotionEvent) -> bool:
        if event.get_action_masked() == MotionEvent.ACTION_UP and self.is_double_tapping:
            if DEBUG:
                print("onDoubleTapEvent, ACTION_UP")
            
            if self.controls is not None:
                self.controls.on_double_tap_progress_up(event.x, event.y)
        
        return True

    def run(self):
        if DEBUG:
            print("Runnable called")
        
        set_double_tapping(False)
        DoubleTapGestureListener.this.set_double_tapping(False)
        
        if self.get_controls() is not None:
            self.get_controls().on_double_tap_finished()
```

Please note that Python does not support direct translation of Java code to Python. The above code has been written in a way that it should be equivalent to the original Java code, but there might be some differences due to the nature of both languages.