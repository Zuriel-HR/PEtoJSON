import r2pipe
import hashlib
import json
import os

def get_file_info(file_path):
    # Obtener nombre y tamaño del archivo
    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)
    
    # Calcular los hashes MD5 y SHA-256
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        while chunk := f.read(8192):
            md5_hash.update(chunk)
            sha256_hash.update(chunk)
    
    file_info = {
        "file_name": file_name,
        "file_size": f"{file_size // 1024}KB",
        "hashes": {
            "md5": md5_hash.hexdigest(),
            "sha256": sha256_hash.hexdigest()
        }
    }
    
    return file_info

def extract_json_data(file_path):
    # Iniciar r2pipe y analizar el archivo
    r2 = r2pipe.open(file_path)
    r2.cmd('aaa')  # Análisis completo

    # Extraer información en JSON
    sections = json.loads(r2.cmd("iSj"))
    imports = json.loads(r2.cmd("iij"))
    strings = json.loads(r2.cmd("izj"))
    resources = json.loads(r2.cmd("irj"))
    metadata = json.loads(r2.cmd("iHj"))
    timestamp = r2.cmd("iHt").strip()
    entropy_data = float(r2.cmd("p= entropy").strip())
    
    # Procesar strings sospechosos (ejemplo básico)
    suspicious_strings = [s['string'] for s in strings['strings'] if "http" in s['string'] or "C2" in s['string'] or "APPDATA" in s['string']]
    
    # Armar estructura JSON
    analysis_data = {
        "compilation_timestamp": timestamp,
        "metadata": {
            "machine": metadata['info']['arch'],
            "linker_version": metadata['info']['binsz'],
            "subsystem": metadata['info']['subsys']
        },
        "pe_header": {
            "address_of_entry_point": metadata['info']['entry'],
            "image_base": metadata['info']['baddr']
        },
        "entropy": entropy_data,
        "imports": {
            "dlls": [
                {
                    "name": dll['name'],
                    "functions": dll['imports']
                } for dll in imports['imports']
            ],
            "suspicious_imports": [imp['name'] for imp in imports['imports'] if imp['name'] in ["WriteProcessMemory", "CreateRemoteThread", "InternetOpenUrlA"]]
        },
        "strings": {
            "total_strings": len(strings['strings']),
            "suspicious_strings": suspicious_strings
        },
        "sections": [
            {
                "name": section['name'],
                "virtual_size": section['vsize'],
                "raw_size": section['size'],
                "entropy": section['entropy']
            } for section in sections
        ],
        "resources": {
            "total_size": len(resources['resources']),
            "details": resources['resources']
        }
    }
    
    r2.quit()  # Cerrar la conexión con r2pipe
    return analysis_data

def main(file_path):
    file_info = get_file_info(file_path)
    analysis_data = extract_json_data(file_path)
    
    final_output = {
        "file_info": file_info,
        "analysis": analysis_data
    }
    
    # Convertir a JSON y guardar en un archivo
    with open("analysis_output.json", "w") as outfile:
        json.dump(final_output, outfile, indent=4)

if __name__ == "__main__":
    file_path = "C:/Users/castr/Downloads/Ledger Live.exe"  # Cambia esto por el path de tu archivo PE
    main(file_path)
