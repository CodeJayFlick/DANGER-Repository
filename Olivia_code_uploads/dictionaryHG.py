student = {}
student["name"] = "ABC"
student["year"] = 1
student["cpi"] = 9.0
student["dept"] = "CSE"
student[("courses",1)] = [ "CS101" , "MA102" , "CS110" ]
student["gg"]=(8,7)
student[5] = False
#student[[6,7]]=90 #TypeError: unhashable type: 'list'
print(student)
#student=student+[3,5] #TypeError: unsupported operand type(s) for +: 'dict' and 'list'
print(student[5])
print("Following are the 2 ways to print the student")
#FIRST_WAY
for k in student:
    print(k,"=",student[k])
#SECOND_WAY	
for k,v in student.items():
    print(k,"=",v)
	
if "cpi" in student:
    print("Student dictionary contains cpi key")
else:
    print("Student dictionary does not contain cpi key")
if "cpi" in student:
    del student["cpi"]
if ('courses',1) in student:#("courses",1) is a key present in student
    del student[5]
print(student)


dict = {'Name': 'Zara', 'Age': 7, "Name": 'Manni'}
print("dict['Name']: ",dict['Name'])
"""
#dict.append(34)#AttributeError: 'dict' object has no attribute 'append'
#dict.insert(2,346)#AttributeError: 'dict' object has no attribute 'insert'
#dict.remove(7)#AttributeError: 'dict' object has no attribute 'remove' 
"""
del dict["Name"] #NoError 
"""we cannot delete a particular element in tuple as it is immutable object whereas we can any particular object delete in dictionary just like lists
"""