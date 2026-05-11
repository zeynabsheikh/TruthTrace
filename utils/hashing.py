import hashlib

def generate_file_hash(file_path):
    # Standard SHA-512 hashing for file integrity
    sha512_hash = hashlib.sha512()
    try:
        with open(file_path, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha512_hash.update(byte_block)
        return sha512_hash.hexdigest()
    except Exception as e:
        return f"Error: {str(e)}"