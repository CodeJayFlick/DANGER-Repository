class App:
    def main(self):
        ivory_tower = IvoryTower()
        proxy = WizardTowerProxy(ivory_tower)
        
        for i in range(5):  # enter 5 wizards
            wizard_name = f"{'Red' if i == 0 else 'White' if i == 1 else 'Black' if i == 2 else 'Green' if i == 3 else 'Brown'} wizard"
            proxy.enter(Wizard(wizard_name))

if __name__ == "__main__":
    App().main()
