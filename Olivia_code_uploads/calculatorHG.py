def loopchoice(a):
    selcList = []
    while a > 0:
        x = input('Chosen value?: ')
        selcList.append(int(x))
        a-=1
    return selcList

def addition (aList) :
    addValues=sum(aList)
    return(addValues)#prints addValues otherwise nothing would print
    
def subtraction(aList):
    i = 0
    for x in aList:
        if i == 0:
           i+=x
        else:
            i-=x
    subValues=i
    return(subValues)
    
def multiplication(aList):
    i=1
    for x in aList:
        i=i*x
    return(i)
    
def division(aList):
    if (aList[1] == 0):
        aList[1] = input("Division by zero is incorrect. Please select another number.")       
    x = aList[0]/aList[1]
    return(x)

def pythagoreanTheorem(aList):
    import math
    if(aList=="a"):
        aSide=int(aList[0])**2-int(aList[1])**2
        math.sqrt(aSide)
        return(aSide)
    elif(aList=="b"):
        varA=int(input("Enter A Value "))
        varC=int(input("Enter C Value "))
        math.sqrt(varB)
        return(varB)
    elif(aList=="c"):
        varA=int(input("Enter A Value "))
        varB=int(input("Enter B Value "))
        varCProd=(varA**2+varB**2)
        math.sqrt(varCProd)
        return(varCProd)

def naturalLog(aList):
    import math
    naturalLogTotal=math.log(aList)    
    return(naturalLogTotal) 

def log(aList):      
    import math
    logTotal= math.log(aList[0],aList[1])
    return(logTotal)

def raiseNumberToPower(aList):
    import math
    raiseTotal= aList[0]**aList[1]
    return(raiseTotal)

def factorial(aList):
    import math
    factorialTotal=math.factorial(aList)
    return(factorialTotal)                  

#0+first value-subtract last one
i=0
combinedTotal=[]
combinedDiff=[]

while i<3:
    x=input("Do you want to use the addition, subtraction, multiplication, divison, natural log, log, raise a number to a power, pythagorean theorem, or factorial? ")
    if (x=="addition"):
        num1=int(input("How many inputs would you like ? "))
        selcs = loopchoice(num1)#can add the inputs where the num1 is for division
        mySum = addition(selcs)
        print(mySum)
        num1+=1
        combinedTotal.append(mySum)
        combinedDiff.append(mySum)
    elif(x=="subtraction"):
        num1=int(input("How many inputs would you like?"))
        selcs=loopchoice(num1)
        myDif=subtraction(selcs)
        print(myDif)
        num1+=1
        combinedTotal.append(myDif)
        combinedDiff.append(myDif)
    elif(x=="multiplication"):
        num1=int(input("How many inputs would you like?"))
        selcs=loopchoice(num1)
        myProd=multiplication(selcs)
        print(myProd)
        num1+=1
        combinedTotal.append(myProd)
        combinedDiff.append(myProd)
    elif(x=="division"):
        num1=int(input("How many inputs would you like?"))
        selcs=loopchoice(2)
        myQuot=float(division(selcs))
        print(myQuot)
        num1+=1
        combinedTotal.append(myQuot)
        combinedDiff.append(myQuot)
    elif(x=="natural log"):
        num1=int(input("What number do you want to take the natural log of? "))
        naturalLogTotal=float(str(naturalLog(num1)))
        print("The natural log of "+str(num1)+" is "+str(naturalLogTotal)+".")
        combinedTotal.append(naturalLogTotal)
        combinedDiff.append(naturalLogTotal)
    elif(x=="log"):
        num1=int(input("How many inputs would you like? Enter 2 here (first input= x value and second input= base value) "))
        selcs=loopchoice(2)
        logValue=float(log(selcs))
        print("The log based on your inputs is "+str(logValue)+".")
        num1+=1
        combinedTotal.append(logValue)
        combinedDiff.append(logValue)
    elif(x=="raise a number to a power"):
        num1=int(input("How many inputs would you like? Enter 2 here (the first number chosen is the base number and the second option will be the exponent"))
        selcs = loopchoice(2)
        myProd=raiseNumberToPower(selcs)
        print(myProd)
        num1+=1
        combinedTotal.append(myProd)
        combinedDiff.append(myProd)
    elif(x=="pythagorean theorem"):
        num1=input("Enter the a and b value of the pythagorean theorem to solve for c. Enter c here. ")
        pythagoreanProduct= str(pythagoreanTheorem(num1))
        print("The value is "+ str(pythagoreanProduct)+".")
        combinedTotal.append(pythagoreanProduct)
        combinedDiff.append(pythagoreanProduct)
    elif(x=="factorial"):
        num1=int(input("What number would you like to take the factorial of? "))
        myFactorial=float(str(factorial(num1)))
        print("The factorial of "+str(num1)+ " is "+str(myFactorial)+".")
        combinedTotal.append(myFactorial)
        combinedDiff.append(myFactorial)
    i+=1
    

for z in combinedTotal:
    print("Your total is "+str(z)+".")  
print("Your sum based on your three totals is "+str(sum(combinedTotal))+".")

for d in combinedDiff:
    i = 0
    for x in combinedDiff:
        if i == 0:
           i+=x
        else:
            i-=x
    y=i
print("Your difference based on your three totals is "+str(y)+".")
    

#the addition, subtraction, multiplication,division,factorial, and natural log all work 100%