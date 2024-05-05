from flask import Flask, request, jsonify
import subprocess
import os
import uuid

app = Flask(__name__)

print("DMG Analyzer")

def analyze_dmg_file(file_path):
    try:
        metadata = {}

        # Use hdiutil to extract meta information about the DMG file
        result = subprocess.run(["hdiutil", "imageinfo", file_path], capture_output=True, text=True)
        if result.returncode == 0:
            info_lines = result.stdout.splitlines()
            for line in info_lines:
                key_value = line.split(":", 1)
                if len(key_value) == 2:
                    key = key_value[0].strip()
                    value = key_value[1].strip()
                    metadata[key] = value

        return {"Metadata": metadata}

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
            unique_filename = str(uuid.uuid4()) + ".dmg"
            file_path = os.path.join("uploads", unique_filename)

            file.save(file_path)

            result = analyze_dmg_file(file_path)

            if os.path.exists(file_path):
                os.remove(file_path)

            return jsonify(result)

    except Exception as e:
        return jsonify({"Error": str(e)})

if __name__ == '__main__':
    app.run(debug=True)
