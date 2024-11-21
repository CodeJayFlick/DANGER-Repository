import logging

class ProjectileStrategy:
    def execute(self):
        logging.info("You shoot the dragon with the magical crossbow and it falls dead on the ground!")

if __name__ == "__main__":
    import logging.config
    logging.config.dictConfig({
        "version": 1,
        "formatters": {
            "default": {"format": "%(asctime)s - %(levelname)-8s [%(filename)s:%(lineno)d] %(message)s"}
        },
        "handlers": {
            "console": {"class": "logging.StreamHandler", "level": logging.INFO}
        },
        "root": {"level": logging.INFO, "handlers": ["console"]}
    })
