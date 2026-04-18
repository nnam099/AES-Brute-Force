"""
aes_engine.py - AES Encryption/Decryption Engine
Minh họa AES với khóa ngắn (16/24/32 bits) được pad thành 16 bytes
"""

import os
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def generate_short_key(bits: int) -> bytes:
    """
    Tạo khóa ngắn và pad thành 16 bytes (AES-128 standard).
    
    Args:
        bits: Độ dài khóa thực tế (1-32 bits)
    
    Returns:
        bytes: Khóa 16 bytes (padded với zeros)
    """
    if bits < 1 or bits > 32:
        raise ValueError(f"Key length {bits} không hợp lệ. Chỉ hỗ trợ 1-32 bits.")
    
    max_val = (2 ** bits) - 1
    rand_int = int.from_bytes(os.urandom(4), 'big') & max_val
    
    # Số bytes cần để lưu (ceil division)
    key_bytes_len = (bits + 7) // 8
    key_part = rand_int.to_bytes(key_bytes_len, byteorder='big')
    
    # Pad với zeros cho đủ 16 bytes (AES-128)
    padded_key = key_part.ljust(16, b'\x00')
    return padded_key


def key_int_to_bytes(key_int: int, key_bits: int) -> bytes:
    """
    Chuyển số nguyên thành key bytes (dùng cho brute-force).
    """
    key_bytes_len = (key_bits + 7) // 8
    key_part = key_int.to_bytes(key_bytes_len, byteorder='big')
    return key_part.ljust(16, b'\x00')


def encrypt_aes(plaintext: str, key_bits: int, key: bytes = None) -> tuple:
    """
    Mã hóa plaintext bằng AES-ECB với khóa ngắn.
    
    Args:
        plaintext: Chuỗi cần mã hóa
        key_bits: Độ dài khóa thực tế (bits)
        key: Key bytes tùy chọn (nếu None thì generate ngẫu nhiên)
    
    Returns:
        tuple: (ciphertext_bytes, key_bytes, key_int)
    """
    if key is None:
        key = generate_short_key(key_bits)
    
    cipher = AES.new(key, AES.MODE_ECB)
    padded_data = pad(plaintext.encode('utf-8'), AES.block_size)
    ciphertext = cipher.encrypt(padded_data)
    
    # Lấy phần key thực tế để tính số nguyên (ceil division, mask để đúng bit count)
    key_bytes_len = (key_bits + 7) // 8
    key_int = int.from_bytes(key[:key_bytes_len], byteorder='big') & ((2 ** key_bits) - 1)
    
    return ciphertext, key, key_int


def decrypt_aes(ciphertext: bytes, key: bytes) -> str:
    """
    Giải mã ciphertext bằng AES-ECB.
    
    Args:
        ciphertext: Dữ liệu đã mã hóa
        key: Key bytes (16 bytes)
    
    Returns:
        str: Plaintext hoặc None nếu thất bại
    """
    try:
        cipher = AES.new(key, AES.MODE_ECB)
        padded_data = cipher.decrypt(ciphertext)
        return unpad(padded_data, AES.block_size).decode('utf-8')
    except Exception:
        return None


def bytes_to_hex(data: bytes) -> str:
    """Chuyển bytes sang chuỗi hex dễ đọc."""
    return data.hex().upper()


def hex_to_bytes(hex_str: str) -> bytes:
    """Chuyển chuỗi hex sang bytes."""
    return bytes.fromhex(hex_str.strip())


if __name__ == "__main__":
    # Test cơ bản
    print("=== Test AES Engine ===")
    test_text = "HELLO WORLD"
    
    for bits in [16, 24, 32]:
        ciphertext, key, key_int = encrypt_aes(test_text, bits)
        decrypted = decrypt_aes(ciphertext, key)
        
        print(f"\n[{bits}-bit key]")
        print(f"  Plaintext : {test_text}")
        print(f"  Key (hex) : {bytes_to_hex(key)}")
        print(f"  Key value : {key_int} (0x{key_int:0{bits//4}X})")
        print(f"  Ciphertext: {bytes_to_hex(ciphertext)}")
        print(f"  Decrypted : {decrypted}")
        print(f"  Match     : {test_text == decrypted}")
