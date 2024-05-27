import os
import pefile
import requests
import json
import subprocess
import re
from flask import Flask, request, jsonify

app = Flask(__name__)

def analyze_pe_file(file_path):
    try:
        pe = pefile.PE(file_path)

        metadata = {
            "Signature": hex(pe.DOS_HEADER.e_magic),
            "Machine": pe.FILE_HEADER.Machine,
            "Number_of_Sections": pe.FILE_HEADER.NumberOfSections,
            "Time_Date_Stamp": pe.FILE_HEADER.TimeDateStamp,
            "Entry_Point": hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint),
            "Image_Base": hex(pe.OPTIONAL_HEADER.ImageBase)
        }

        # Verify digital signature
        print("Verifying digital signature...")
        signature_status, publisher = verify_digital_signature(file_path)
        metadata["Digital_Signature"] = signature_status
        metadata["Publisher"] = publisher
        print(f"Digital Signature Status: {signature_status}")
        print(f"Publisher: {publisher}")

        # Get DLLs and functions
        dependencies = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8').lower()
            functions = [imp.name.decode('utf-8') if imp.name else f"Ordinal {imp.ordinal}" for imp in entry.imports]
            dependencies.append({"DLL": dll_name, "Functions": functions})
        print("Extracted DLLs and Functions:")

        # Query NVD API for vulnerabilities
        vulnerabilities = []
        for dependency in dependencies:
            dll_name = dependency["DLL"]
            print(f"Querying NVD API for vulnerabilities related to {dll_name}...")
            cve_items = query_cve_items_for_dll(dll_name)
            print(f"Found {len(cve_items)} CVE items for {dll_name}")
            affected_resources = extract_affected_resources(cve_items, dependency["Functions"])
            if affected_resources:
                vulnerabilities.append({"DLL": dll_name, "Affected_Resources": affected_resources})
            else:
                print(f"No affected resources found for {dll_name}")
        
        print("Analysis completed successfully.")
        return {"Metadata": metadata, "Dependencies": dependencies, "Vulnerabilities": vulnerabilities}

    except Exception as e:
        print(f"Error analyzing PE file: {e}")
        return {"Error": str(e)}

def verify_digital_signature(file_path):
    try:
        ps_command = f"powershell.exe -Command \"& {{$file = '{file_path}'; $signature = Get-AuthenticodeSignature -FilePath $file; if ($signature.Status -eq 'Valid') {{ 'Valid' }} elseif ($signature.Status -eq 'NotSigned') {{ 'NotSigned' }} else {{ 'Invalid' }}; $signature.SignerCertificate.Subject}}\""
        result = subprocess.run(ps_command, capture_output=True, text=True, shell=True)

        if result.returncode != 0:
            print(f"PowerShell error: {result.stderr}")
            return "Verification failed", None

        output_lines = result.stdout.splitlines()
        signature_status = output_lines[0].strip()
        publisher = output_lines[1].strip()
        return signature_status, publisher

    except Exception as e:
        print(f"Error verifying digital signature: {e}")
        return "Verification failed", None

def query_cve_items_for_dll(dll_name):
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={dll_name}&resultsPerPage=10"
        print(f"URL IS: {url}")
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        return data.get("vulnerabilities", [])
    except Exception as e:
        print(f"Error querying NVD API for DLL {dll_name}: {e}")
        return []

def extract_affected_resources(cve_items, functions):
    try:
        affected_resources = []
        for cve_item in cve_items:
            description = cve_item.get("cve", {}).get("descriptions", [{}])[0].get("value", "").lower()
            matches = re.findall(r'\bin\b ([^.,;]+)', description)
            for match in matches:
                if any(func.lower() in match for func in functions):
                    affected_resources.append(match)
        return affected_resources

    except Exception as e:
        print(f"Error extracting affected resources: {e}")
        return []

@app.route('/analyze', methods=['POST'])
def analyze():
    if 'file' not in request.files:
        return jsonify({"error": "No file part"}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({"error": "No selected file"}), 400

    file_path = os.path.join("/tmp", file.filename)
    file.save(file_path)

    result = analyze_pe_file(file_path)
    os.remove(file_path)
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)
