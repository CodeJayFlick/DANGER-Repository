class Car:
    def __init__(self, bodyType, engineType, brand, model):
        self.bodyType = bodyType
        self.engineType = engineType
        self.brand = brand
        self.model = model
        
    def paintCost(self):
        bodyType = self.bodyType
        if bodyType == "truck":
            return "$200"
        
        elif bodyType == "sedan":
            return "$150"
        
        elif bodyType == "coupe":
            return "$100"
        
        else:
            raise NameError("Invaild body type")
    
    def topSpeed(self):
        bodyType = self.bodyType
        engineType = self.engineType
        baseTopSpeed = 100
        bodyTypeDict = {'truck': 1.0, 'sedan': 1.3, 'coupe': 1.5}
        engineTypeDict = {'large': 1.2, 'medium': 1.1, 'small': 1.0}
        try:
            return baseTopSpeed * bodyTypeDict[bodyType] * engineTypeDict[engineType]
        except Exception:
            raise NameError("Invaild body type or engine type")
    
    def setBodyType(self, bodyType):
        self.bodyType = bodyType
        
    def getBodyType(self):
        return self.bodyType
    
    def setEngineType(self, engineType):
        self.engineType = engineType
        
    def getEngineType(self):
        return self.engineType
    
    def setBrand(self, brand):
        self.brand = brand
        
    def getBrand(self):
        return self.brand
    
    def setModel(self, model):
        self.model = model
        
    def getModel(self):
        return self.model
    
print("Truck = 1, Sedan = 2, Coupe = 3")    
bodyType = input("Choose a body type: ")
bodyTypeDict = {"1":'truck', "2":'sedan', "3":'coupe'}
bodyType = bodyTypeDict[bodyType]
print("Large = 1, Medium = 2, Small = 1")
engineType = input("Choose an engine type: ")
engineTypeDict = {"1":'large', "2":'medium', "3":'small'}
engineType = engineTypeDict[engineType]
print("BMW = 1, Toyota = 2, Honda = 3")
brand = input("Choose a brand: ")

if int(brand) == 1:
    brand = 'BMW'
    print("330i = 1, 550i = 2, 750i = 3")
    model = input("Choose a model: ")
    modelDict = {"1":'330i', "2":'550i', "3":'750i'}
    model = modelDict[model]
    
elif int(brand) == 2:
    brand = 'Toyota'
    print("Corolla = 1, Camry = 2, Prius = 3")
    model = input("Choose a model: ")
    modelDict = {"1":'Corolla', "2":'Camry', "3":'Prius'}
    model = modelDict[model]
    
elif int(brand) == 3:
    brand = 'Honda'
    print("Civic = 1, Accord = 2, CRV = 3")
    model = input("Choose a model: ")
    modelDict = {"1":'Civic', "2":'Accord', "3":'CRV'}
    model = modelDict[model]
    

newCar = Car(bodyType, engineType, brand, model)
print()
print("Body type: " + str(newCar.getBodyType()))
print("Engine type: " + str(newCar.getEngineType()))
print("Brand: " + str(newCar.getBrand()))
print("Model: " + str(newCar.getModel()))
print("Your total paint cost is " + str(newCar.paintCost()))
print("Your top speed is " + str(newCar.topSpeed()) + "mph")
