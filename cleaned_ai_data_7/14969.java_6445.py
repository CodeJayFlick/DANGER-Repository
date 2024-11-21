import logging

# The MIT License
# Copyright (c) 2014-2021 Ilkka Seppälä

class App:
    logger = logging.getLogger(__name__)

    def __init__(self):
        self.logger.info("Db seeding: 1 user: {'ignite1771', amount=1000.0}, 2 products: {'computer': price=800.0, 'car': price=20000.0}")
        Db.seed_user('ignite1771', 1000.0)
        Db.seed_item('computer', 800.0)
        Db.seed_item('car', 20000.0)

    def main(self):
        application_services = ApplicationServicesImpl()
        receipt = None

        self.logger.info("[REQUEST] User: abc123 buy product: tv")
        receipt = application_services.logged_in_user_purchase("abc123", "tv")
        if receipt:
            receipt.show()

        MaintenanceLock.set_lock(False)
        self.logger.info("[REQUEST] User: abc123 buy product: tv")
        receipt = application_services.logged_in_user_purchase("abc123", "tv")
        if receipt:
            receipt.show()

        self.logger.info("[REQUEST] User: ignite1771 buy product: tv")
        receipt = application_services.logged_in_user_purchase("ignite1771", "tv")
        if receipt:
            receipt.show()

        self.logger.info("[REQUEST] User: ignite1771 buy product: car")
        receipt = application_services.logged_in_user_purchase("ignite1771", "car")
        if receipt:
            receipt.show()

        self.logger.info("[REQUEST] User: ignite1771 buy product: computer")
        receipt = application_services.logged_in_user_purchase("ignite1771", "computer")
        if receipt:
            receipt.show()


if __name__ == "__main__":
    app = App()
    app.main()
