#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script để tạo các file test mẫu
"""

import os
import hashlib
import binascii

def create_eicar_file():
    """Tạo EICAR test file"""
    eicar_string = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*'
    eicar_bytes = eicar_string.encode('utf-8')
    
    filepath = 'eicar_test.txt'
    with open(filepath, 'wb') as f:
        f.write(eicar_bytes)
    
    md5 = hashlib.md5(eicar_bytes).hexdigest()
    sha256 = hashlib.sha256(eicar_bytes).hexdigest()
    hex_content = binascii.hexlify(eicar_bytes).decode('utf-8').upper()
    
    print(f"Created: {filepath}")
    print(f"  MD5: {md5}")
    print(f"  SHA256: {sha256}")
    print(f"  Hex: {hex_content[:80]}...")
    print(f"  Size: {len(eicar_bytes)} bytes")
    
    return filepath, md5, sha256, hex_content

def create_test_file_with_pattern():
    """Tạo file test chứa một pattern từ database"""
    # Lấy một pattern từ database để test
    pattern_hex = "6A6176612F6C616E672F436C6173734C6F61646572"  # "java/lang/ClassLoader" in hex
    pattern_bytes = binascii.unhexlify(pattern_hex)
    
    # Tạo file test với pattern này
    test_content = b"Test file content " + pattern_bytes + b" more content"
    
    filepath = 'test_pattern.txt'
    with open(filepath, 'wb') as f:
        f.write(test_content)
    
    print(f"\nCreated: {filepath}")
    print(f"  Contains pattern: java/lang/ClassLoader")
    print(f"  Size: {len(test_content)} bytes")
    
    return filepath

if __name__ == '__main__':
    os.makedirs('test_samples', exist_ok=True)
    os.chdir('test_samples')
    
    print("Creating test files...\n")
    
    # Tạo EICAR file
    eicar_file, md5, sha256, hex_content = create_eicar_file()
    
    # Tạo file với pattern
    pattern_file = create_test_file_with_pattern()
    
    print("\n✓ Test files created successfully!")
    print("\nYou can upload these files to test the scanner:")
