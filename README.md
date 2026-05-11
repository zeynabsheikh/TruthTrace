#  TruthTrace: Suspicious Evidence Detection System

TruthTrace is a digital forensic web application designed to verify the integrity of images and documents. It helps detect if a file has been tampered with or edited by analyzing its metadata and digital fingerprint.

##  Key Features
- **File Integrity Check:** Generates a unique SHA-512 hash for every uploaded file.
- **Metadata Analysis:** Scans for hidden EXIF data and editing software traces.
- **Tamper Detection:** Flags files with missing metadata or inconsistent timestamps.
- **Secure Architecture:** Built with security best practices (CSRF protection, Input validation).

---

##  Team Roles & Responsibilities

### **Member 1: Project Lead & Security Architect**
- Set up the **Flask framework** and core project structure.
- Implemented **SHA-512 Hashing** for digital integrity verification.
- Developed the **Main Backend Engine** and Routing.
- Designed the **Modern Dark UI** for Upload and Report pages.

### **Member 2: Forensic Logic Analyst**
- Developing the **Metadata Extraction** module using Pillow.
- Implementing the **Suspicion Scoring** logic.
- Identifying software traces (Photoshop, Canva, etc.).

### **Member 3: UI/UX & Auth Lead**
- Developing the **User Authentication** system (Login/Register).
- Managing the **SQLite Database** for user records.
- Refining the **Result Dashboard** for detailed analysis reports.

---

##  Tech Stack
- **Backend:** Python (Flask)
- **Frontend:** HTML5, CSS3 (Modern Dark Theme)
- **Database:** SQLite
- **Libraries:** Pillow, Hashlib, Flask-WTF

##  How to Setup and Run

To get this project running on your local machine, follow these steps in your terminal:

### 1. Clone the repository
```bash
git clone [https://github.com/zeynabsheikh/TruthTrace.git](https://github.com/zeynabsheikh/TruthTrace.git)
cd TruthTrace
```
### 2. Install Dependencies
- You need to install the following Python libraries:
```bash
pip install flask flask-wtf Pillow
```
### 3.Run the Application
- Run the Application
  ```bash
  python App.py
  ```

  

