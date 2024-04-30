from flask import Flask, request, jsonify
import os
import pefile
import uuid

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

        dependencies = []

        # Analyze the import table
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            dll_name = entry.dll.decode('utf-8').lower()
            functions = [imp.name.decode('utf-8') if imp.name else "Ordinal {}".format(imp.ordinal) for imp in entry.imports]
            dependencies.append({"DLL": dll_name, "Functions": functions})

        print("Metadata:", metadata, "dependencies:", dependencies)
        return {"Metadata": metadata, "Dependencies": dependencies}

    except Exception as e:
        return {"Error": str(e)}
    


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

            result = None
            with open(file_path, "rb") as f: 
                file.save(f)
                f.close() 
                result = analyze_pe_file(file_path)

            if os.path.exists(file_path):
                os.remove(file_path)

            return jsonify(result)

    except Exception as e:
        return jsonify({"Error": str(e)})

if __name__ == '__main__':
    # Run the app and listen on all network interfaces (0.0.0.0)
    app.run(debug=True, host='0.0.0.0', port=5000)
