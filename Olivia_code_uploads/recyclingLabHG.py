x=input("What do you want to recycle? Paper, Batteries, Glass, Used Oil, Household Waste, Tires ")
if(x=="Paper"):
    print('Paper makes up 23 percent of municipal solid waste (trash) generated each year, more than any other material. Americans recycled about 68 percent of the paper they used in 2018. This recovered paper is used to make new paper products, saving trees and other natural resources. Most community or office recycling programs accept paper and paper products. Check what your community or office program accepts before you put it in the bin. When you go shopping, look for products that are made from recycled paper.')
elif(x=="Batteries"):
    y=input("What kind of batteries are you going to recycle? Dry-Cell Batteries, Lithium-ion Batteries, Lithium-Metal Batteries, Lead-Acid Batteries, Other Rechargeable Batteries?")
    if(y=="Dry-Cell Batteries"):
        print("Dry-Cell Batteries are used in a variety of electronics and include alkaline and carbon zinc (9-volt, D, C, AA, AAA), mercuric-oxide (button, some cylindrical and rectangular), and silver-oxide and zinc-air (button). Look for in-store recycling bins or community collection events to dispose of these batteries.")
    elif(y=="Lithium-ion Batteries"):
        print("Lithium-ion Batteries are used in many rechargeable products such as electronics, toys, wireless headphones, handheld power tools, small and large appliances, electric vehicles, and electrical energy storage systems. Do not put them in the trash or municipal recycling bins. Household lithium-ion batteries can be brought to dedicated in-store recycling bins or household hazardous waste collection events for disposal. Medium- and large-scale electric vehicle or energy storage batteries should be returned to the manufacturer, automobile dealer, or installation company for management at end of life.")
    elif(y=="Lithium-Metal Batteries"):
        print("Lithium-Metal Batteries are similar to lithium-ion batteries but are not rechargeable. They are commonly used in products such as cameras, watches, remote controls, handheld games, and smoke detectors. Do not put them in the trash or municipal recycling bins: look for dedicated in-store recycling bins or household hazardous waste collection events for disposal.")
    elif(y=="Lead-Acid Batteries"):
        print("Lead-Acid Batteries can be found in automobiles, boats, snowmobiles, motorcycles, golf carts, wheelchairs, and other large transportation vehicles. Return lead-acid batteries to a battery retailer or local household hazardous waste collection program; do not put lead-acid batteries in the trash or municipal recycling bins.")
    elif(y=="Other Rechargeable Batteries"):
        print("Other Rechargeable Batteries include nickel cadmium, nickel metal hydride, and nickel-zinc batteries. These batteries can be found in cordless power tools, cordless phones, cell phones, digital cameras, and small electronics. Do not put these rechargeable batteries in the trash or municipal recycling bins: look for dedicated in-store recycling bins or household hazardous waste collection events for disposal.")
elif(x=="Plastics"):
    z=input("What kind of plastic are you going to recycle? PETE, HDPE, V, LDPE, PP, PS, OTHER")
    if(z=="PETE"):
        print("PETE, or polyethylene terephthalate, is considered among the safest plastics, though some studies do indicate that repeated use of the same PETE bottle or container could cause leaching of DEHP, an endocrine-disrupting phthalate and probable human carcinogen.")
    elif(z=="HDPE"):
        print("Some reusable sports bottles are a #2 (highdensity polyethylene), and these are far preferable to the #7 versions.") 
    elif(z=="V"):
        print("PVC, or polyvinyl chloride, is commonly considered the most damaging of all plastics. It releases carcinogenic dioxins into the environment when manufactured or incinerated and can leach phthalates with use.")
    elif(z=="LDPE"):
        print("Low-density polyethylene are considered reasonably safe.")
    elif(z=="PP"):
        print("Polypropylene are considered reasonably safe.")
    elif(z=="PS"):
        print("You’ll find this code on your foam, or polystyrene, cups and “to go” boxes, as well as some clear cups and containers. Polystyrene can leach styrene, a possible human carcinogen.")
    else:
        print("There is not a specific way to recycle these items.")
elif(x=="Glass"):
    print("Glass, especially glass food and beverage containers, can be recycled over and over again. In the United States in 2018, 12.3 million tons of glass were generated, 25 percent of which was recovered for recycling. Making new glass from recycled glass is typically cheaper than using raw materials. Most curbside community recycling programs accept different glass colors and types mixed together, and then glass is sorted at the recovery facility. Check with your local program to see if you need to separate your glass or if it can be mixed together.")
elif(x=="Used Oil"):
    print("Never dump your used motor oil down the drain — the used oil from one oil change can contaminate one million gallons of fresh water. By recycling your used oil you not only help keep our water supply clean, but help reduce American dependence on foreign oil. It takes 42 gallons of crude oil, but only one gallon of used oil, to produce 2.5 quarts of new motor oil. Many garages and auto-supply stores that sell motor oil also accept oil for recycling.")
elif(x=="Household Hazardous Waste"):
    print("Leftover household products that contain corrosive, toxic, ignitable, or reactive ingredients are considered to be house hazardous waste.Products such as paints, cleaners, oils, batteries, and pesticides that contain potentially hazardous ingredients require special care when you dispose of them. HHW may be dangerous to people or bad for the environment if poured down the drain, dumped on the ground, or thrown out with regular trash.")
elif(x=="Tires"):
    print("Disease-carrying pests such as rodents may live in tire piles. Tire piles can also catch on fire. Most garages are required to accept and recycle your used tires when you have new ones installed. You may be able to return used tires to either a tire retailer or a local recycling facility that accepts tires. Some communities will hold collection events for used tires.")