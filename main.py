from flask import Flask, request, jsonify
import os
import pefile
import requests
import uuid
import time
import subprocess

app = Flask(__name__)

print("EXE PARSER")


def extract_version_info(pe):
    version_info = {}
    if hasattr(pe, 'VS_FIXEDFILEINFO') and pe.VS_FIXEDFILEINFO:
        fixed_file_info = pe.VS_FIXEDFILEINFO[0]
        version_info['FileVersion'] = "{}.{}.{}.{}".format(
            (fixed_file_info.FileVersionMS >> 16) & 0xFFFF,
            fixed_file_info.FileVersionMS & 0xFFFF,
            (fixed_file_info.FileVersionLS >> 16) & 0xFFFF,
            fixed_file_info.FileVersionLS & 0xFFFF
        )
        version_info['ProductVersion'] = "{}.{}.{}.{}".format(
            (fixed_file_info.ProductVersionMS >> 16) & 0xFFFF,
            fixed_file_info.ProductVersionMS & 0xFFFF,
            (fixed_file_info.ProductVersionLS >> 16) & 0xFFFF,
            fixed_file_info.ProductVersionLS & 0xFFFF
        )

    if hasattr(pe, 'FileInfo') and pe.FileInfo:
        for fileinfo in pe.FileInfo:
            if hasattr(fileinfo, 'Key') and fileinfo.Key == 'StringFileInfo':
                for st in fileinfo.StringTable:
                    for entry in st.entries.items():
                        version_info[entry[0]] = entry[1]

    return version_info


def filter_vulnerabilities(vulnerabilities, version_info, functions):
    filtered_vulnerabilities = []
    product_name = version_info.get('ProductName', '').lower()
    company_name = version_info.get('CompanyName', '').lower()

    for vuln in vulnerabilities:
        description = vuln.get('cve', {}).get('description', {}).get('description_data', [])
        for desc in description:
            desc_text = desc['value'].lower()
            if product_name in desc_text or company_name in desc_text:
                vulnerable_functions = [func for func in functions if func.lower() in desc_text]
                filtered_vulnerabilities.append({"Vulnerability": vuln, "Vulnerable_Functions": vulnerable_functions})
                break

    return filtered_vulnerabilities


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

        # Extract version info
        version_info = extract_version_info(pe)
        metadata.update(version_info)

        # Verify digital signature
        signature_status = verify_digital_signature(file_path)
        metadata["Digital_Signature"] = signature_status

        dependencies = []

        # Analyze the import table
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8').lower()
            functions = [imp.name.decode('utf-8') if imp.name else "Ordinal {}".format(imp.ordinal) for imp in entry.imports]
            dependencies.append({"DLL": dll_name, "Functions": functions})

        vulnerabilities = []
        for dependency in dependencies:
            dll_name = dependency["DLL"]
            functions = dependency["Functions"]
            vulnerability_info = query_nvd_api(dll_name)
            filtered_vulns = filter_vulnerabilities(vulnerability_info, version_info, functions)
            vulnerabilities.append({"DLL": dll_name, "Vulnerabilities": filtered_vulns})

        return {"Metadata": metadata, "Dependencies": dependencies, "Vulnerabilities": vulnerabilities}

    except Exception as e:
        return {"Error": str(e)}


def verify_digital_signature(file_path):
    try:
        # Run osslsigncode to verify digital signature
        result = subprocess.run(['osslsigncode', 'verify', file_path], capture_output=True, text=True)
        output = result.stdout

        # Check if "Signature verified successfully" is present in the output
        if "Signature verified successfully" in output:
            return "Valid"
        else:
            return "Invalid"

    except Exception as e:
        print(f"Error verifying digital signature: {e}")
        return "Verification failed"


def query_nvd_api(dll_name):
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={dll_name}"
        print("Querying NVD API for:", dll_name)
        response = requests.get(url, timeout=10)
        response.raise_for_status()
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        if not vulnerabilities:
            vulnerabilities = data.get("result", {}).get("CVE_Items", [])
        time.sleep(1)
        return vulnerabilities
    except requests.exceptions.RequestException as e:
        print(f"Error querying NVD API for {dll_name}: {e}")
        return []


@app.route('/analyze', methods=['POST'])
def analyze():
    try:
        if 'file' not in request.files:
            return jsonify({"Error": "No file part"})

        file = request.files['file']

        if file.filename == '':
            return jsonify({"Error": "No selected file"})

        if file:
            # Generate a unique filename using UUID
            unique_filename = str(uuid.uuid4()) + ".exe"
            file_path = os.path.join("uploads", unique_filename)

            file.save(file_path)

            result = analyze_pe_file(file_path)

            if os.path.exists(file_path):
                os.remove(file_path)

            return jsonify(result)

    except Exception as e:
        return jsonify({"Error": str(e)})

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=8080)
