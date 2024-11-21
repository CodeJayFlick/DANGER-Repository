class WAVEDataType:
    MAGIC = bytes([0x52, 0x49, 0x46, 0x00, 0x00, 0x00, 0x00, 0x57, 0x41, 0x56, 0x45])
    MAGIC_MASK = bytes([0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00])

    def __init__(self):
        self.__init__()

    def __init__(self, dtm=None):
        super().__init__(None, "WAVE-Sound", dtm)

    @property
    def length(self):
        return -1

    def get_length(self, buf: bytearray, max_len: int) -> int:
        try:
            if not self.check_magic(buf):
                return -1
            return (int.from_bytes(buf[4:], 'big') + 8)
        except Exception as e:
            print(f"Invalid WAV data at {buf[:4]}")
        return -1

    def check_magic(self, buf: bytearray) -> bool:
        for i in range(len(MAGIC)):
            if MAGIC[i] != (buf[i] & MAGIC_MASK[i]):
                return False
        return True

    @property
    def can_specify_length(self):
        return False

    def clone(self, dtm=None) -> 'WAVEDataType':
        if dtm == self.get_data_type_manager():
            return self
        return WAVEDataType(dtm)

    @property
    def description(self):
        return "WAVE sound stored within program"

    @property
    def mnemonic(self):
        return "WAV"

    def get_representation(self, buf: bytearray, settings=None, length=-1) -> str:
        return "<WAVE-Resource>"

class WAVEData:
    AUDIO_ICON = ResourceManager.load_image("images/audio-volume-medium.png")

    def __init__(self, bytes: bytearray):
        self.bytes = bytes

    def clicked(self, event):
        try:
            clip = AudioSystem.get_clip()
            ais = AudioSystem.get_audio_stream(new ByteArrayInputStream(bytes))
            clip.open(ais)
            clip.start()
        except (UnsupportedAudioFileException, IOException, LineUnavailableException) as e:
            print(f"Unable to play audio: {e}")

    def get_image_icon(self):
        return self.AUDIO_ICON

class WAVEDataType(BuiltIn, Dynamic):
    pass
