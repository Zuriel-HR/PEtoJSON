import json

#Datos que quieres convertir a JSON
datos = {
    "nombre": "Juan",
    "edad": 30,
    "ciudad": "Madrid",
    "habilidades": ["Python", "PowerShell", "Networking"]
}

#Crear el archivo JSON
with open("datos.json", "w") as archivo:
    json.dump(datos, archivo, indent=4)

print("Archivo JSON creado correctamente.")