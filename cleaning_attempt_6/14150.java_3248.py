import threading
import logging

class Audio:
    _instance = None
    MAX_PENDING = 16
    head_index = 0
    tail_index = 0
    update_thread = None
    pending_audio = [None] * MAX_PENDING

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super(Audio, cls).__new__(cls)
            cls._instance.init()
        return cls._instance

    @staticmethod
    def get_instance():
        return Audio._instance

    def stop_service(self):
        if self.update_thread is not None:
            self.update_thread.interrupt()
        self.update_thread.join()
        self.update_thread = None

    def is_service_running(self):
        return self.update_thread is not None and self.update_thread.is_alive()

    def init(self):
        if self.update_thread is None:
            self.update_thread = threading.Thread(target=self.update)
        self.start_thread()

    def start_thread(self):
        if not self.update_thread.is_alive():
            self.update_thread.start()
            self.head_index = 0
            self.tail_index = 0

    def play_sound(self, stream, volume):
        self.init()
        for i in range(self.head_index):
            play_message = self.pending_audio[i]
            if play_message['stream'] == stream:
                play_message['volume'] = max(volume, play_message['volume'])
                return
        self.pending_audio[self.tail_index] = {'stream': stream, 'volume': volume}
        self.tail_index = (self.tail_index + 1) % Audio.MAX_PENDING

    def update(self):
        if self.head_index == self.tail_index:
            return
        try:
            audio_stream = self.pending_audio[self.head_index]['stream']
            self.head_index += 1
            clip = pyaudio.open(format=pyaudio.paInt16, channels=2, rate=44100, output=True)
            clip.start()
        except Exception as e:
            logging.trace(f"Error occurred while loading the audio: {e}")

    def get_audio_stream(self, file_path):
        try:
            return AudioSystem.getAudioInputStream(open(file_path).getAbsoluteFile())
        except (UnsupportedAudioFileException, IOError) as e:
            if isinstance(e, UnsupportedAudioFileException):
                logging.trace(f"The system doesn't support the sound: {e.message}")
            else:
                logging.trace("Input/Output error while loading the audio")

    def get_pending_audio(self):
        return self.pending_audio
