import android
from abc import ABCMeta, abstractmethod
from enum import Enum, unique
from threading import Thread
from time import sleep
from typing import Any, Dict, List, Optional, Tuple

class ScanActivity:
    INTENT_EXTRA_SCENE_TRANSITION_X = "scene_transition_x"
    INTENT_EXTRA_SCENE_TRANSITION_Y = "scene_transition_y"
    INTENT_EXTRA_RESULT = "result"

    def __init__(self):
        self.viewModel = ViewModelProvider(self).get(ScanViewModel)

    @staticmethod
    def start_for_result(activity: Any, view: Optional[Any], request_code: int) -> None:
        if view is not None:
            x, y = get_view_location(view)
            intent = Intent(activity, ScanActivity.class)
            intent.putExtra(INTENT_EXTRA_SCENE_TRANSITION_X, (x + view.getWidth() // 2))
            intent.putExtra(INTENT_EXTRA_SCENE_TRANSITION_Y, (y + view.getHeight() // 2))
            activity.startActivityForResult(intent, request_code)

    def on_create(self, savedInstanceState: Optional[Dict[str, Any]]) -> None:
        super().on_create(savedInstanceState)
        self.vibrator = Vibrator(self.getSystemService(Context.VIBRATOR_SERVICE))

        if not hasattr(self.viewModel, 'show_permission_warn_dialog'):
            self.viewModel.show_permission_warn_dialog.observe(self, lambda v: WarnDialogFragment.show(getSupportFragmentManager(), R.string.scan_camera_permission_dialog_title,
                                                                                                        getString(R.string.scan_camera_permission_dialog_message)))

    def on_resume(self) -> None:
        super().on_resume()
        maybe_open_camera()

    def on_pause(self) -> None:
        self.camera_handler.post(close_runnable)

    @staticmethod
    def get_view_location(view: Any) -> Tuple[int, int]:
        location = [0] * 2
        view.getLocationOnScreen(location)
        return (location[0], location[1])

class WarnDialogFragment(Dialog):
    FRAGMENT_TAG = "WarnDialogFragment"

    @classmethod
    def show(cls, fm: FragmentManager, title_res_id: int, message: str) -> None:
        new_fragment = cls()
        args = Bundle()
        args.putInt("title", title_res_id)
        args.putString("message", message)
        new_fragment.setArguments(args)
        new_fragment.show(fm, FRAGMENT_TAG)

    def on_create_dialog(self, savedInstanceState: Optional[Dict[str, Any]]) -> Dialog:
        bundle = self.getArguments()
        dialog_builder = WarnDialogFragment.warn(getActivity(), bundle.getInt("title"), bundle.getString(
            "message"))
        return dialog_builder.create()

class ViewModelProvider:
    @classmethod
    def get(cls, activity: Any) -> Any:
        pass

@unique
class DecodeHintType(Enum):
    NEED_RESULT_POINT_CALLBACK = 1

class QRCodeReader:
    def decode(self, bitmap: BinaryBitmap) -> Result:
        # todo implement decoding logic here
        return None

if __name__ == "__main__":
    activity = ScanActivity()
    activity.on_create(None)
