#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script để trích xuất virus signatures từ các file database ClamAV
và lưu theo định dạng: số_virus\nname:type:*:hex_signature
"""

import tarfile
import re
import binascii
from pathlib import Path

def parse_ndb_line(line):
    """
    Parse dòng NDB format: Name:Type:Target:Offset:HexSignature
    Hoặc format đơn giản: Hash:Type:*:Name (từ .hdb)
    """
    line = line.strip()
    if not line or line.startswith('#') or ':' not in line:
        return None
    
    parts = line.split(':')
    if len(parts) >= 5:
        name = parts[0]
        sig_type = parts[1]
        # Bỏ qua target và offset, lấy hex signature (có thể có nhiều phần nếu có :)
        hex_sig = ':'.join(parts[4:])  # Lấy tất cả phần sau offset
        
        # Kiểm tra nếu name là hash (chỉ chứa hex) và phần cuối là tên virus
        if len(name) == 32 and all(c in '0123456789abcdefABCDEF' for c in name):
            # Format ngược: Hash:Type:*:Name -> chuyển thành Name:Type:*:Hash
            virus_name = parts[-1] if len(parts) > 4 else name
            return f"{virus_name}:{sig_type}:*:{name}"
        
        # Format: Name:Type:*:HexSignature
        return f"{name}:{sig_type}:*:{hex_sig}"
    elif len(parts) >= 3:
        # Có thể là format đơn giản hơn
        name = parts[0]
        sig_type = parts[1]
        hex_sig = ':'.join(parts[2:])
        
        # Kiểm tra nếu name là hash
        if len(name) == 32 and all(c in '0123456789abcdefABCDEF' for c in name):
            virus_name = parts[-1] if len(parts) > 2 else name
            return f"{virus_name}:{sig_type}:*:{name}"
        
        return f"{name}:{sig_type}:*:{hex_sig}"
    return None

def parse_ldb_line(line):
    """
    Parse dòng LDB format (logic database)
    Format: Name;Engine:...;Target:...;Conditions;HexSignature
    """
    line = line.strip()
    if not line or line.startswith('#') or ';' not in line:
        return None
    
    # LDB dùng dấu ; để phân tách
    parts = line.split(';')
    if len(parts) >= 2:
        name = parts[0]
        
        # Tìm type từ Engine hoặc Target
        sig_type = '3'  # Default
        for part in parts[1:]:
            if part.startswith('Target:'):
                # Target:1 -> type 1, Target:3 -> type 3, etc.
                target_match = re.search(r'Target:(\d+)', part)
                if target_match:
                    sig_type = target_match.group(1)
                break
        
        # Tìm hex signature - thường là phần cuối cùng (sau dấu ; cuối)
        # Hex signature có thể chứa wildcards như {4-12}, {-36}, *?, etc.
        hex_sig = ''
        for i in range(len(parts) - 1, 0, -1):
            part = parts[i]
            # Nếu phần này chứa hex pattern hoặc wildcards
            if re.search(r'[0-9a-fA-F]{4,}|[{}*?]', part, re.IGNORECASE):
                hex_sig = ';'.join(parts[i:])
                break
        
        if not hex_sig and len(parts) > 1:
            # Nếu không tìm thấy, lấy phần cuối
            hex_sig = parts[-1]
        
        if hex_sig:
            # Loại bỏ các dấu `:*:` thừa
            hex_sig = hex_sig.lstrip(':*:')
            return f"{name}:{sig_type}:*:{hex_sig}"
    return None

def parse_hdb_line(line):
    """
    Parse dòng HDB format (hash database)
    """
    line = line.strip()
    if not line or line.startswith('#') or ':' not in line:
        return None
    
    parts = line.split(':')
    if len(parts) >= 2:
        hash_value = parts[0]  # MD5 hash
        name = parts[1] if len(parts) > 1 else 'Unknown'
        # Convert hash sang hex nếu cần
        return f"{name}:3:*:{hash_value}"
    return None

def extract_signatures_from_tar(tar_path, output_file):
    """
    Extract signatures từ file tar archive
    """
    signatures = []
    
    try:
        with tarfile.open(tar_path, 'r') as tar:
            members = tar.getmembers()
            
            for member in members:
                if member.isfile():
                    filename = member.name
                    ext = Path(filename).suffix.lower()
                    
                    # Chỉ xử lý các file database có tên virus (bỏ .hdb/.mdb vì chỉ có hash)
                    if ext in ['.ndb', '.ldb', '.msb', '.pdb', '.wdb', '.cdb', '.crb']:
                        try:
                            f = tar.extractfile(member)
                            if f:
                                content = f.read().decode('utf-8', errors='ignore')
                                lines = content.split('\n')
                                
                                for line in lines:
                                    sig = None
                                    line = line.strip()
                                    if not line:
                                        continue
                                    
                                    if ext == '.ndb':
                                        sig = parse_ndb_line(line)
                                    elif ext == '.ldb':
                                        sig = parse_ldb_line(line)
                                    elif ext in ['.hdb', '.mdb']:
                                        sig = parse_hdb_line(line)
                                    else:
                                        # Thử parse như NDB trước, nếu không được thì thử LDB
                                        sig = parse_ndb_line(line)
                                        if not sig:
                                            sig = parse_ldb_line(line)
                                    
                                    if sig:
                                        # Đảm bảo format: Name:Type:*:HexSignature
                                        parts = sig.split(':')
                                        if len(parts) >= 2:
                                            name = parts[0]
                                            sig_type = parts[1]
                                            # Lấy phần hex (từ phần thứ 3 trở đi, bỏ qua `*` nếu có)
                                            hex_parts = parts[2:]
                                            # Loại bỏ `*` nếu có
                                            hex_parts = [p for p in hex_parts if p != '*']
                                            hex_sig = ':'.join(hex_parts) if hex_parts else ''
                                            
                                            # Chỉ thêm nếu có hex signature
                                            if hex_sig:
                                                sig = f"{name}:{sig_type}:*:{hex_sig}"
                                                signatures.append(sig)
                        except Exception as e:
                            print(f"  ⚠ Lỗi khi đọc {filename}: {e}")
                            continue
    
    except Exception as e:
        print(f"✗ Lỗi khi mở {tar_path}: {e}")
    
    return signatures

def main():
    current_dir = Path(__file__).parent
    
    # Tìm các file unpacked
    unpacked_files = list(current_dir.glob('*.unpacked'))
    
    if not unpacked_files:
        print("Không tìm thấy file .unpacked nào")
        return
    
    print(f"Tìm thấy {len(unpacked_files)} file unpacked:")
    for f in unpacked_files:
        print(f"  - {f.name}")
    
    all_signatures = []
    
    # Extract signatures từ tất cả các file
    print("\n=== TRÍCH XUẤT SIGNATURES ===\n")
    for unpacked_file in unpacked_files:
        print(f"Đang xử lý: {unpacked_file.name}")
        sigs = extract_signatures_from_tar(unpacked_file, None)
        print(f"  ✓ Tìm thấy {len(sigs)} signatures")
        all_signatures.extend(sigs)
    
    # Loại bỏ duplicates
    unique_signatures = list(dict.fromkeys(all_signatures))  # Giữ thứ tự
    
    print(f"\nTổng số signatures: {len(all_signatures)}")
    print(f"Số signatures unique: {len(unique_signatures)}")
    
    # Ghi ra file
    output_file = current_dir / 'virus_signatures.txt'
    with open(output_file, 'w', encoding='utf-8') as f:
        # Dòng đầu: số lượng virus
        f.write(f"{len(unique_signatures)}\n")
        # Các dòng sau: signatures
        for sig in unique_signatures:
            f.write(f"{sig}\n")
    
    print(f"\n✓ Đã lưu {len(unique_signatures)} signatures vào: {output_file.name}")
    
    # Hiển thị vài ví dụ
    print("\nVí dụ 5 signatures đầu tiên:")
    for i, sig in enumerate(unique_signatures[:5], 1):
        print(f"  {i}. {sig[:100]}..." if len(sig) > 100 else f"  {i}. {sig}")

if __name__ == '__main__':
    main()
