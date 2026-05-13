from PIL import Image, ExifTags
import os
import datetime

class ForensicAnalyzer:
    def __init__(self):
        self.suspicion_score = 0
        self.findings = []
        self.editing_software_keywords = [
            'photoshop', 'canva', 'gimp', 'affinity', 'paint.net',
            'adobe', 'lightroom', 'pixlr', 'fotor', 'picmonkey'
        ]

    def analyze_image(self, file_path):
        self.suspicion_score = 0
        self.findings = []

        if not os.path.exists(file_path):
            return {"error": "File not found"}

        try:
            with Image.open(file_path) as img:
                # Check 1: EXIF Data Analysis
                exif_data = img._getexif()
                if exif_data is None:
                    self.findings.append("No EXIF data found - File may be stripped of metadata")
                    self.suspicion_score += 30
                else:
                    self._analyze_exif_data(exif_data)

                # Check 2: Check for editing software traces
                self._check_software_traces(exif_data)

                # Check 3: File size anomalies
                file_size = os.path.getsize(file_path)
                if file_size < 1024 * 5:  # Less than 5KB
                    self.findings.append("Suspicious file size - too small for a valid image")
                    self.suspicion_score += 20

                # Check 4: Image dimensions analysis
                width, height = img.size
                if width % 8 != 0 or height % 8 != 0:
                    self.findings.append("Unusual dimensions - may indicate editing")
                    self.suspicion_score += 10

                return {
                    "score": self.suspicion_score,
                    "findings": self.findings,
                    "status": "SUSPICIOUS" if self.suspicion_score > 40 else "POSSIBLY EDITED" if self.suspicion_score > 20 else "CLEAN"
                }

        except Exception as e:
            return {"error": "Analysis failed: {}".format(str(e))}

    def _analyze_exif_data(self, exif_data):
        for tag_id, value in exif_data.items():
            tag_name = ExifTags.TAGS.get(tag_id, tag_id)

            # Check for timestamp inconsistencies
            if 'DateTime' in tag_name:
                try:
                    timestamp = datetime.datetime.strptime(value, '%Y:%m:%d %H:%M:%S')
                    if timestamp.year < 2000:
                        self.findings.append("Suspicious timestamp: {}".format(value))
                        self.suspicion_score += 15
                except:
                    self.findings.append("Invalid timestamp format: {}".format(value))
                    self.suspicion_score += 10

            # Check for multiple editing software traces
            if 'Software' in tag_name:
                software_name = value.lower()
                for keyword in self.editing_software_keywords:
                    if keyword in software_name:
                        self.findings.append("Detected editing software: {}".format(value))
                        self.suspicion_score += 40

    def _check_software_traces(self, exif_data):
        if exif_data:
            for tag_id, value in exif_data.items():
                tag_name = ExifTags.TAGS.get(tag_id, tag_id)
                if 'Software' in tag_name:
                    software = str(value)
                    if 'Photoshop' in software:
                        self.findings.append("PHOTOSHOP DETECTED - High suspicion")
                        self.suspicion_score += 50
                    elif 'Canva' in software:
                        self.findings.append("CANVA DETECTED - Medium suspicion")
                        self.suspicion_score += 30
