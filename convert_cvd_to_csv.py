#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Script để chuyển đổi các file ClamAV database (.cvd) sang định dạng CSV
"""

import csv
import os
import re
import gzip
import shutil
import tarfile
import base64
import binascii
from datetime import datetime
from pathlib import Path

def parse_cvd_header(header_line):
    """
    Parse header của file CVD
    Format: ClamAV-VDB:date:version:signatures:functionality:md5:signature:builder:timestamp
    """
    # Tách header, nhưng chỉ lấy phần text trước khi có binary data
    clean_line = header_line.split('\x00')[0] if '\x00' in header_line else header_line
    clean_line = clean_line.strip()
    
    # Tách các phần bằng dấu :
    parts = clean_line.split(':')
    if len(parts) >= 9:
        # Làm sạch signature field (base64 encoded)
        signature = parts[6]
        signature_base64 = ''
        signature_hex = ''
        
        if signature:
            # Lấy phần base64 (loại bỏ các ký tự không in được)
            signature_clean = ''.join(c for c in signature if c.isprintable() or c in ['+', '/', '='])
            # Tách phần base64 (trước khi có ký tự không hợp lệ)
            # Base64 chỉ chứa A-Z, a-z, 0-9, +, /, =
            base64_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=')
            signature_base64 = ''.join(c for c in signature_clean if c in base64_chars)
            
            # Thử decode base64 và convert sang hex
            if signature_base64:
                try:
                    # Thêm padding nếu cần (base64 cần độ dài chia hết cho 4)
                    missing_padding = len(signature_base64) % 4
                    if missing_padding:
                        signature_base64 += '=' * (4 - missing_padding)
                    
                    # Decode base64
                    decoded_bytes = base64.b64decode(signature_base64, validate=True)
                    # Convert sang hex (uppercase, không có 0x prefix)
                    signature_hex = binascii.hexlify(decoded_bytes).decode('utf-8').upper()
                except Exception as e:
                    # Thử lại với padding khác hoặc không validate
                    try:
                        # Thử decode không validate (cho phép ký tự không hợp lệ)
                        decoded_bytes = base64.b64decode(signature_base64, validate=False)
                        signature_hex = binascii.hexlify(decoded_bytes).decode('utf-8').upper()
                    except Exception as e2:
                        # Nếu vẫn không được, báo lỗi
                        signature_hex = f"Lỗi decode: {str(e2)}"
        
        # Làm sạch timestamp (có thể có binary data)
        timestamp = parts[8].split()[0] if parts[8] else ''
        
        return {
            'format': parts[0],
            'date': parts[1],
            'version': parts[2],
            'signatures': parts[3],
            'functionality': parts[4],
            'md5': parts[5],
            'signature_base64': signature_base64,  # Giữ nguyên toàn bộ
            'signature_hex': signature_hex,  # Giữ nguyên toàn bộ (không giới hạn)
            'builder': parts[7],
            'timestamp': timestamp
        }
    return None

def unpack_cvd_file(cvd_path):
    """
    Unpack file CVD - giải nén dữ liệu gzip bên trong
    Trả về đường dẫn file đã unpack hoặc None nếu lỗi
    """
    try:
        output_path = cvd_path.with_suffix('.unpacked')
        
        with open(cvd_path, 'rb') as f:
            # Đọc toàn bộ file vào memory để tìm gzip magic number
            data = f.read()
            
            # Tìm magic number của gzip: 1f 8b (0x1f 0x8b)
            gzip_start = data.find(b'\x1f\x8b')
            
            if gzip_start < 0:
                print(f"  ✗ Không tìm thấy dữ liệu gzip trong file")
                return None
            
            # Lấy phần dữ liệu gzip
            gzip_data = data[gzip_start:]
            
            # Giải nén dữ liệu gzip
            try:
                decompressed = gzip.decompress(gzip_data)
                
                # Ghi ra file
                with open(output_path, 'wb') as out:
                    out.write(decompressed)
                
                print(f"  ✓ Đã unpack: {output_path.name} ({len(decompressed):,} bytes)")
                return output_path
            except Exception as e:
                print(f"  ✗ Lỗi khi giải nén gzip: {e}")
                return None
                
    except Exception as e:
        print(f"  ✗ Lỗi khi unpack file: {e}")
        return None

def analyze_cvd_file(file_path, unpacked_path=None):
    """
    Phân tích file CVD và trích xuất thông tin
    """
    file_info = {
        'filename': os.path.basename(file_path),
        'filepath': file_path,
        'size_bytes': 0,
        'unpacked_size_bytes': 0,
        'unpacked_size_mb': 0,
        'total_lines': 0,
        'header_parsed': None,
        'has_binary_data': False,
        'is_unpacked': unpacked_path is not None
    }
    
    try:
        file_size = os.path.getsize(file_path)
        file_info['size_bytes'] = file_size
        file_info['size_mb'] = round(file_size / (1024 * 1024), 2)
        
        # Nếu có file unpacked, phân tích file đó
        file_to_analyze = unpacked_path if unpacked_path and unpacked_path.exists() else file_path
        if unpacked_path and unpacked_path.exists():
            unpacked_size = os.path.getsize(unpacked_path)
            file_info['unpacked_size_bytes'] = unpacked_size
            file_info['unpacked_size_mb'] = round(unpacked_size / (1024 * 1024), 2)
        
        # Đọc header từ file gốc (header chỉ có trong file .cvd gốc)
        with open(file_path, 'rb') as f:
            first_line = f.readline()
            if first_line:
                try:
                    # Tìm vị trí null byte đầu tiên (bắt đầu binary data)
                    null_pos = first_line.find(b'\x00')
                    if null_pos > 0:
                        header_bytes = first_line[:null_pos]
                    else:
                        # Tìm vị trí ký tự không in được đầu tiên
                        for i, byte in enumerate(first_line):
                            if byte < 32 and byte not in [9, 10, 13]:  # Tab, LF, CR
                                header_bytes = first_line[:i]
                                break
                        else:
                            header_bytes = first_line
                    
                    header_text = header_bytes.decode('utf-8', errors='ignore')
                    if header_text.startswith('ClamAV-VDB:'):
                        file_info['header_parsed'] = parse_cvd_header(header_text)
                except Exception as e:
                    file_info['header_error'] = str(e)
        
        # Phân tích file unpacked nếu có, nếu không thì phân tích file gốc
        if unpacked_path and unpacked_path.exists():
            # Đọc file unpacked để đếm dòng và kiểm tra
            with open(unpacked_path, 'rb') as f:
                # Đếm số dòng
                file_info['total_lines'] = sum(1 for _ in f)
                
                # Kiểm tra binary data
                f.seek(0)
                sample = f.read(10000)  # Đọc 10KB đầu
                file_info['has_binary_data'] = any(b < 32 and b not in [9, 10, 13] for b in sample[:1000])
        else:
            # Phân tích file gốc
            with open(file_path, 'rb') as f:
                file_info['total_lines'] = sum(1 for _ in f)
                file_info['has_binary_data'] = True  # File gốc luôn có binary
            
    except Exception as e:
        file_info['error'] = str(e)
    
    return file_info

def convert_cvd_to_csv(cvd_files, output_csv):
    """
    Chuyển đổi thông tin từ các file CVD sang CSV
    Trả về danh sách các tuple (cvd_file, unpacked_path)
    """
    all_data = []
    unpacked_files = []
    
    # Bước 1: Unpack các file .cvd
    print("\n=== BƯỚC 1: UNPACK CÁC FILE .CVD ===\n")
    for cvd_file in cvd_files:
        print(f"Đang unpack: {cvd_file.name}")
        unpacked_path = unpack_cvd_file(cvd_file)
        if unpacked_path:
            unpacked_files.append((cvd_file, unpacked_path))
        else:
            print(f"  ⚠ Không thể unpack {cvd_file.name}, sẽ phân tích file gốc")
            unpacked_files.append((cvd_file, None))
    
    # Bước 2: Phân tích và chuyển đổi sang CSV
    print("\n=== BƯỚC 2: PHÂN TÍCH VÀ CHUYỂN ĐỔI SANG CSV ===\n")
    for cvd_file, unpacked_path in unpacked_files:
        print(f"Đang xử lý: {cvd_file.name}")
        file_info = analyze_cvd_file(cvd_file, unpacked_path)
        all_data.append(file_info)
    
    # Chuẩn bị dữ liệu cho CSV
    csv_rows = []
    for data in all_data:
        row = {
            'Tên file': data['filename'],
            'Đường dẫn': data['filepath'],
            'Kích thước gốc (bytes)': data['size_bytes'],
            'Kích thước gốc (MB)': data.get('size_mb', 0),
            'Đã unpack': 'Có' if data.get('is_unpacked', False) else 'Không',
            'Kích thước unpacked (bytes)': data.get('unpacked_size_bytes', 0),
            'Kích thước unpacked (MB)': data.get('unpacked_size_mb', 0),
            'Tổng số dòng': data['total_lines'],
            'Có dữ liệu binary': 'Có' if data['has_binary_data'] else 'Không',
        }
        
        # Thêm thông tin từ header nếu có
        if data['header_parsed']:
            header = data['header_parsed']
            row.update({
                'Ngày tạo': header.get('date', ''),
                'Phiên bản': header.get('version', ''),
                'Số signatures': header.get('signatures', ''),
                'Functionality': header.get('functionality', ''),
                'MD5': header.get('md5', ''),
                'Signature (Base64)': header.get('signature_base64', ''),
                'Signature (Hex)': header.get('signature_hex', ''),
                'Builder': header.get('builder', ''),
                'Timestamp': header.get('timestamp', '')
            })
        else:
            row.update({
                'Ngày tạo': '',
                'Phiên bản': '',
                'Số signatures': '',
                'Functionality': '',
                'MD5': '',
                'Signature (Base64)': '',
                'Signature (Hex)': '',
                'Builder': '',
                'Timestamp': ''
            })
        
        if 'error' in data:
            row['Lỗi'] = data['error']
        else:
            row['Lỗi'] = ''
        
        csv_rows.append(row)
    
    # Ghi ra file CSV
    if csv_rows:
        fieldnames = [
            'Tên file', 'Đường dẫn', 'Kích thước gốc (bytes)', 'Kích thước gốc (MB)',
            'Đã unpack', 'Kích thước unpacked (bytes)', 'Kích thước unpacked (MB)',
            'Tổng số dòng', 'Có dữ liệu binary',
            'Ngày tạo', 'Phiên bản', 'Số signatures', 'Functionality',
            'MD5', 'Signature (Base64)', 'Signature (Hex)', 'Builder', 'Timestamp', 'Lỗi'
        ]
        
        with open(output_csv, 'w', newline='', encoding='utf-8-sig') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(csv_rows)
        
        print(f"\nĐã tạo file CSV: {output_csv}")
        print(f"Tổng số file đã xử lý: {len(csv_rows)}")
    else:
        print("Không có dữ liệu để ghi vào CSV")
    
    return unpacked_files

def extract_tar_and_create_csv(unpacked_files, output_csv):
    """
    Extract các file tar và tạo CSV chứa danh sách các file bên trong
    """
    print("\n=== BƯỚC 3: EXTRACT TAR VÀ TẠO CSV CHI TIẾT ===\n")
    
    all_files_data = []
    
    for cvd_file, unpacked_path in unpacked_files:
        if not unpacked_path or not unpacked_path.exists():
            continue
        
        print(f"Đang extract và phân tích: {unpacked_path.name}")
        
        try:
            with tarfile.open(unpacked_path, 'r') as tar:
                members = tar.getmembers()
                print(f"  Tìm thấy {len(members)} file trong archive")
                
                for member in members:
                    # Chuyển đổi timestamp sang định dạng ngày tháng
                    mod_date = datetime.fromtimestamp(member.mtime).strftime('%Y-%m-%d %H:%M:%S') if member.mtime else ''
                    
                    file_info = {
                        'File gốc': cvd_file.name,
                        'Archive': unpacked_path.name,
                        'Tên file trong archive': member.name,
                        'Kích thước (bytes)': member.size,
                        'Kích thước (KB)': round(member.size / 1024, 2) if member.size else 0,
                        'Loại file': 'Thư mục' if member.isdir() else ('Link' if member.issym() else 'File'),
                        'Quyền truy cập': oct(member.mode),
                        'Ngày chỉnh sửa': mod_date,
                    }
                    
                    # Xác định loại file dựa trên extension
                    ext = Path(member.name).suffix.lower()
                    if ext == '.cbc':
                        file_info['Loại database'] = 'Bytecode'
                    elif ext in ['.hdb', '.hdu', '.hsb', '.hsu']:
                        file_info['Loại database'] = 'Hash'
                    elif ext in ['.ndb', '.ndu']:
                        file_info['Loại database'] = 'NDB'
                    elif ext in ['.mdb', '.mdu']:
                        file_info['Loại database'] = 'MD5'
                    elif ext in ['.ldb', '.ldu']:
                        file_info['Loại database'] = 'Logic'
                    elif ext in ['.msb', '.msu']:
                        file_info['Loại database'] = 'MSB'
                    elif ext in ['.idb']:
                        file_info['Loại database'] = 'IDB'
                    elif ext in ['.pdb', '.wdb', '.cdb', '.crb']:
                        file_info['Loại database'] = 'Pattern'
                    elif ext in ['.fp', '.sfp']:
                        file_info['Loại database'] = 'False Positive'
                    elif ext in ['.cfg', '.info', '.ign', '.ign2', '.ftm']:
                        file_info['Loại database'] = 'Config/Info'
                    elif member.name == 'COPYING':
                        file_info['Loại database'] = 'License'
                    else:
                        file_info['Loại database'] = 'Khác'
                    
                    all_files_data.append(file_info)
        
        except Exception as e:
            print(f"  ✗ Lỗi khi extract {unpacked_path.name}: {e}")
    
    # Ghi ra CSV
    if all_files_data:
        fieldnames = [
            'File gốc', 'Archive', 'Tên file trong archive', 'Kích thước (bytes)',
            'Kích thước (KB)', 'Loại file', 'Loại database', 'Quyền truy cập', 'Ngày chỉnh sửa'
        ]
        
        with open(output_csv, 'w', newline='', encoding='utf-8-sig') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            writer.writerows(all_files_data)
        
        print(f"\n✓ Đã tạo file CSV chi tiết: {output_csv}")
        print(f"  Tổng số file trong tất cả archives: {len(all_files_data)}")
    else:
        print("Không có dữ liệu để ghi vào CSV chi tiết")

def main():
    # Tìm tất cả file .cvd trong thư mục hiện tại
    current_dir = Path(__file__).parent
    cvd_files = list(current_dir.glob('*.cvd'))
    
    if not cvd_files:
        print("Không tìm thấy file .cvd nào trong thư mục hiện tại")
        return
    
    print(f"Tìm thấy {len(cvd_files)} file .cvd:")
    for f in cvd_files:
        print(f"  - {f.name}")
    
    # Tên file output
    output_csv = current_dir / 'clamav_database_info.csv'
    output_csv_detailed = current_dir / 'clamav_database_files.csv'
    
    # Chuyển đổi
    unpacked_files_list = convert_cvd_to_csv(cvd_files, output_csv)
    
    # Tạo CSV chi tiết chứa danh sách các file trong tar archives
    if unpacked_files_list:
        extract_tar_and_create_csv(unpacked_files_list, output_csv_detailed)
    
    print("\n✓ Hoàn thành!")
    print(f"\nCác file CSV đã được tạo:")
    print(f"  1. {output_csv.name} - Thông tin tổng quan về các file .cvd")
    print(f"  2. {output_csv_detailed.name} - Danh sách chi tiết các file trong archives")

if __name__ == '__main__':
    main()
