from flask import Flask, render_template, request, url_for
import os
from utils.hashing import generate_file_hash

app = Flask(__name__)
app.secret_key = "infosec_secret_key"

UPLOAD_FOLDER = 'uploads'
# Only allow specific file types for security
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'docx'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    # Security check: Does the file have an allowed extension?
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file selected"
    
    file = request.files['file']
    
    if file.filename == '':
        return "No file selected"

    # Security check before saving
    if file and allowed_file(file.filename):
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)
        
        # SHA-512 Integrity Check
        file_hash = generate_file_hash(file_path)
        
        # NOTE FOR MEMBER 2: 
        # Your metadata analysis results will be called here.
        # Example: analysis_results = metadata_checker.check(file_path)
        
        return render_template('report.html', 
                               filename=file.filename, 
                               file_hash=file_hash)
    else:
        return "Security Error: File type not allowed!"

if __name__ == '__main__':
    app.run(debug=True)