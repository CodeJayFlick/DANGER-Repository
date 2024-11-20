import logging

# Define a logger instance
logging.basicConfig(level=logging.INFO)
LOGGER = logging.getLogger(__name__)

class Nazgul:
    _instances = {}

    def __new__(cls, name):
        if name not in cls._instances:
            cls._instances[name] = super(Nazgul, cls).__new__(cls)
        return cls._instances[name]

    @classmethod
    def getInstance(cls, name):
        return Nazgul(name)

class App:

    def main(self):

        # Eagerly initialized multiton
        LOGGER.info("KHAMUL={}", Nazgul.getInstance(NazgulName.KHAMUL))
        LOGGER.info("MURAZOR={}", Nazgul.getInstance(NazgulName.MURAZOR))
        LOGGER.info("DWAR={}", Nazgul.getInstance(NazgulName.DWAR))
        LOGGER.info("JI_INDUR={}", Nazgul.getInstance(NazgulName.JI_INDUR))
        LOGGER.info("AKHORAHIL={}", Nazgul.getInstance(NazgulName.AKHORAHIL))
        LOGGER.info("HOARMURATH={}", Nazgul.getInstance(NazgulName.HOARMURATH))
        LOGGER.info("ADUNAPHEL={}", Nazgul.getInstance(NazgulName.ADUNAPHEL))
        LOGGER.info("REN={}", Nazgul.getInstance(NazgulName.REN))
        LOGGER.info("UVATHA={}", Nazgul.getInstance(NazgulName.UVATHA))

class NazgulEnum:
    KHAMUL = None
    MURAZOR = None
    DWAR = None
    JI_INDUR = None
    AKHORAHIL = None
    HOARMURATH = None
    ADUNAPHEL = None
    REN = None
    UVATHA = None

App().main()
