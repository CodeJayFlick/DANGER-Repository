class AUDataType:
    MAGIC = bytes([0x2E, 0x73, 0x6e, 0x64])  # '.snd'
    MAGIC_MASK = b'\xFF\xFF\xFF\xFF'

    def __init__(self):
        self.__init__(None)

    def __init__(self, dtm=None):
        super().__init__(None, "AU-Sound", dtm)

    @property
    def length(self):
        return -1

    def get_length(self, buf: bytearray, max_len: int) -> int:
        try:
            if not self.check_magic(buf):
                print("Invalid AU magic number")
                return -1
            data_offset = GhidraBigEndianDataConverter().get_int(buf, 4)
            data_size = GhidraBigEndianDataConverter().get_int(buf, 8)
            total_size = data_offset + data_size
            return total_size
        except Exception as e:
            print(f"Invalid AU data at {buf[:4]}")
        return -1

    def check_magic(self, buf: bytearray) -> bool:
        for i in range(len(AUDataType.MAGIC)):
            if buf[i] != (AUDataType.MAGIC[i] & AUDataType.MAGIC_MASK[i]):
                return False
        return True

    @property
    def can_specify_length(self):
        return False

    def clone(self, dtm=None) -> 'AUDataType':
        if dtm == self.get_data_type_manager():
            return self
        return AUDataType(dtm)

    @property
    def description(self):
        return "AU sound stored within program"

    @property
    def mnemonic(self):
        return "AU"

    def get_representation(self, buf: bytearray, settings=None, length=-1) -> str:
        return "<AU-Representation>"

class AUData:
    AUDIO_ICON = ResourceManager().load_image("images/audio-volume-medium.png")

    def __init__(self, bytes: bytearray):
        self.bytes = bytes

    def clicked(self, event):
        try:
            clip = AudioSystem.get_clip()
            ais = AudioSystem.get_audio_stream(new_bytes_io_stream(self.bytes))
            clip.open(ais)
            clip.start()
        except (UnsupportedAudioFileException, IOException, LineUnavailableException) as e:
            print("Unable to play audio", e)

    def get_image_icon(self):
        return self.AUDIO_ICON

class AUDataTypeManager(DataType):
    pass
