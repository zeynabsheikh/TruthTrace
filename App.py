from flask import Flask, render_template, request, url_for, redirect, flash
import os
from utils.hashing import generate_file_hash
from utils.forensic import ForensicAnalyzer

app = Flask(__name__)
app.config['SECRET_KEY'] = 'infosec_secret_key_secure_2024'

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'pdf', 'docx'}

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# Initialize forensic analyzer (Member 2)
forensic_analyzer = ForensicAnalyzer()

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return render_template('upload.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file selected', 'error')
        return redirect(url_for('home'))

    file = request.files['file']

    if file.filename == '':
        flash('No file selected', 'error')
        return redirect(url_for('home'))

    if file and allowed_file(file.filename):
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        file.save(file_path)

        # SHA-512 Integrity Check (Member 1)
        file_hash = generate_file_hash(file_path)

        # Forensic Analysis (Member 2)
        forensic_results = forensic_analyzer.analyze_image(file_path)

        return render_template('report.html',
                               filename=file.filename,
                               file_hash=file_hash,
                               forensic_findings=forensic_results.get('findings', []),
                               suspicion_score=forensic_results.get('score', 0),
                               status=forensic_results.get('status', 'Unknown'))
    else:
        flash('Security Error: File type not allowed!', 'error')
        return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True)
