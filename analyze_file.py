import r2pipe
import json
import hashlib

def export_to_json(data, output_file):
    """Exporta los datos a un archivo JSON."""
    with open(output_file, 'w') as json_file:
        json.dump(data, json_file, indent=4)

def calculate_sha256(file_path):
    """Calcula el hash SHA256 del archivo."""
    sha256_hash = hashlib.sha256()
    with open(file_path, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def analyze_file(file_path):
    # Abre el archivo con radare2 usando r2pipe
    r2 = r2pipe.open(file_path)
    r2.cmd("aaa")  # Realiza un análisis completo

    # Características del archivo
    characteristics = {
        "hash": calculate_sha256(file_path),
        "entropy": None,
        "metadata": {
            "compilation_timestamp": None,
            "filename": file_path,
            "language": None
        },
        "imports": [],
        "resources": {
            "total_size": None,
            "details": []
        },
        "digital_signature": None
    }

    # Extraer entropía
    entropy = r2.cmdj("p=j entropy")
    if entropy:
        characteristics["entropy"] = entropy.get("entropy")

    # Extraer timestamp de compilación
    timestamp = r2.cmdj("ij").get("bins", [{}])[0].get("timestamp")
    if timestamp:
        characteristics["metadata"]["compilation_timestamp"] = timestamp

    # Extraer el lenguaje (por ejemplo, PE o ELF)
    lang = r2.cmdj("ij").get("info", {}).get("format")
    if lang:
        characteristics["metadata"]["language"] = lang

    # Extraer importaciones
    imports = r2.cmdj("iij")
    if imports:
        for imp in imports:
            characteristics["imports"].append({
                "name": imp.get("name"),
                "type": "API"  # Esto se puede ajustar si se obtiene más información específica
            })

    # Extraer recursos (solo para archivos PE o ELF)
    resources = r2.cmdj("iRj")
    if resources:
        total_size = sum([res.get("size", 0) for res in resources])
        characteristics["resources"]["total_size"] = total_size
        for res in resources:
            characteristics["resources"]["details"].append({
                "id": res.get("vaddr"),
                "name": res.get("name")
            })

    # Extraer información de la firma digital (si aplica)
    signature_info = r2.cmdj("iSj")
    if signature_info:
        characteristics["digital_signature"] = bool(signature_info)

    # Cierra la conexión con r2
    r2.quit()

    # Retorna las características en formato JSON
    return json.dumps(characteristics, indent=4)

if __name__ == "__main__":
    file_path = "D:/ARCHIVOS/IZHR/ESCUELA/OneDrive - Instituto Politecnico Nacional/IPN-UPIITA/10MO SEMESTRE/PT I/Proyecto/Pruebas/Ledger Live.exe"  
    result = analyze_file(file_path)
    print(result)
    # Exportar los datos a un archivo JSON llamado "analysis_result.json"
    export_to_json(result, "analysis_result.json")

