import hashlib

def generate_file_hash(file_path):
    """Generate SHA-512 hash of a file for integrity verification"""
    sha512_hash = hashlib.sha512()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha512_hash.update(byte_block)
        return sha512_hash.hexdigest()
    except Exception as e:
        return f"Error: {str(e)}"