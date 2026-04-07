#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VirusTotal-like Web Application
Flask server để scan file với virus signatures
"""

import os
import hashlib
import re
import binascii
from flask import Flask, render_template, request, jsonify, send_from_directory
from werkzeug.utils import secure_filename
from pathlib import Path
import time
import bisect

try:
    import ahocorasick
    AHO_CORASICK_AVAILABLE = True
except ImportError:
    AHO_CORASICK_AVAILABLE = False
    print("Warning: pyahocorasick not installed. Pattern matching will be slower.")

try:
    from ml.inference import predict_malware_cnn, MODEL_PATH as ML_MODEL_PATH
except ImportError:
    predict_malware_cnn = None
    ML_MODEL_PATH = None

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'doc', 'docx', 'xls', 'xlsx', 
                                     'exe', 'dll', 'zip', 'rar', '7z', 'jpg', 'jpeg', 
                                     'png', 'gif', 'html', 'htm', 'js', 'php', 'py'}

# Tạo thư mục uploads nếu chưa có
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Cache để lưu signatures (load một lần khi start)
virus_signatures = []
hash_signatures = []  # Sorted list cho binary search
pattern_signatures = []  # Patterns cho Aho-Corasick
pattern_map = {}  # Map pattern bytes -> sig_data
aho_automaton = None  # Aho-Corasick automaton
signatures_loaded = False

def load_signatures():
    """Load virus signatures từ file và tách thành hash và pattern"""
    global virus_signatures, hash_signatures, pattern_signatures, pattern_map, aho_automaton, signatures_loaded
    
    if signatures_loaded:
        return
    
    signatures_file = Path('db/virus_signatures.txt')
    if not signatures_file.exists():
        print(f"Warning: {signatures_file} not found!")
        return
    
    print("Loading virus signatures...")
    start_time = time.time()
    
    hash_sigs = []
    pattern_sigs = []
    
    with open(signatures_file, 'r', encoding='utf-8') as f:
        lines = f.readlines()
        # Bỏ qua dòng đầu (số lượng)
        for line in lines[1:]:
            line = line.strip()
            if not line or ':' not in line:
                continue
            
            parts = line.split(':')
            if len(parts) >= 4:
                # Kiểm tra format đặc biệt: Size:Hash:*:Name (như EICAR)
                # Nếu parts[0] là số và parts[1] là hash 32 hoặc 64 ký tự hex
                if parts[0].isdigit() and len(parts[1]) in [32, 64] and parts[2] == '*':
                    # Format: Size:Hash:*:Name
                    size = parts[0]
                    hash_val = parts[1].upper()
                    name = ':'.join(parts[3:]) if len(parts) > 3 else 'Unknown'
                    
                    sig_data = {
                        'name': name,
                        'type': 'hash',
                        'hex_signature': hash_val
                    }
                    virus_signatures.append(sig_data)
                    # Thêm vào hash signatures
                    hash_sigs.append((hash_val, sig_data))
                else:
                    # Format thông thường: Name:Type:*:HexSignature
                    name = parts[0]
                    sig_type = parts[1]
                    # Bỏ qua phần "*"
                    hex_sig = ':'.join(parts[3:]) if len(parts) > 3 else ''
                    
                    if hex_sig:
                        sig_data = {
                            'name': name,
                            'type': sig_type,
                            'hex_signature': hex_sig
                        }
                        virus_signatures.append(sig_data)
                        
                        # Phân loại: hash (32 hoặc 64 ký tự hex thuần) vs pattern
                        clean_sig = re.sub(r'\{[^}]+\}', '', hex_sig)
                        clean_sig = re.sub(r'\*', '', clean_sig)
                        clean_sig = re.sub(r'\?', '', clean_sig)
                        clean_sig = re.sub(r'[^0-9a-fA-F]', '', clean_sig)
                        
                        # Nếu là hash (32 hoặc 64 ký tự hex thuần, không có wildcards)
                        if len(clean_sig) in [32, 64] and len(clean_sig) == len(re.sub(r'[^0-9a-fA-F]', '', hex_sig)):
                            hash_sigs.append((clean_sig.upper(), sig_data))
                        else:
                            # Pattern với wildcards hoặc hex pattern
                            # Chỉ lấy pattern đủ dài (>= 16 hex chars = 8 bytes) để giảm false positive
                            if len(clean_sig) >= 16:  # Tăng từ 8 lên 16 để tránh pattern quá ngắn
                                pattern_sigs.append((clean_sig.upper(), sig_data))
    
    # Sắp xếp hash signatures cho binary search
    hash_sigs.sort(key=lambda x: x[0])
    hash_signatures = hash_sigs
    
    # Build Aho-Corasick automaton cho patterns
    if AHO_CORASICK_AVAILABLE and pattern_sigs:
        print("Building Aho-Corasick automaton...")
        automaton = ahocorasick.Automaton()
        pattern_map_local = {}
        
        for pattern, sig_data in pattern_sigs:
            try:
                # Aho-Corasick yêu cầu string, không phải bytes
                # Pattern đã là hex string, dùng trực tiếp
                # Lưu mapping: pattern hex string -> sig_data
                pattern_map_local[pattern] = sig_data
                # Add vào automaton: word=pattern_hex_string, value=pattern_hex_string
                automaton.add_word(pattern, pattern)
            except Exception as e:
                # Bỏ qua pattern không hợp lệ
                continue
        
        automaton.make_automaton()
        aho_automaton = automaton
        pattern_map = pattern_map_local
        pattern_signatures = pattern_sigs
        print(f"Built automaton with {len(pattern_map_local)} patterns")
    else:
        pattern_signatures = pattern_sigs
        pattern_map = {}
    
    signatures_loaded = True
    elapsed = time.time() - start_time
    print(f"Loaded {len(virus_signatures)} signatures in {elapsed:.2f} seconds")
    print(f"  - Hash signatures: {len(hash_signatures)}")
    print(f"  - Pattern signatures: {len(pattern_signatures)}")

def allowed_file(filename):
    """Kiểm tra extension file có được phép"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

def calculate_file_hash(file_path):
    """Tính MD5 và SHA256 hash của file"""
    md5_hash = hashlib.md5()
    sha256_hash = hashlib.sha256()
    
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            md5_hash.update(chunk)
            sha256_hash.update(chunk)
    
    return md5_hash.hexdigest(), sha256_hash.hexdigest()

def hex_to_bytes(hex_str):
    """Convert hex string sang bytes, xử lý wildcards"""
    try:
        # Loại bỏ các wildcards như {4-12}, {-36}, *?, etc.
        # Tạm thời chỉ lấy phần hex thuần
        clean_hex = re.sub(r'\{[^}]+\}', '', hex_str)  # Loại bỏ {4-12}
        clean_hex = re.sub(r'\*', '', clean_hex)  # Loại bỏ *
        clean_hex = re.sub(r'\?', '', clean_hex)  # Loại bỏ ?
        clean_hex = re.sub(r'[^0-9a-fA-F]', '', clean_hex)  # Chỉ giữ hex
        
        if len(clean_hex) % 2 != 0:
            clean_hex = clean_hex[:-1]  # Bỏ ký tự cuối nếu lẻ
        
        return binascii.unhexlify(clean_hex)
    except:
        return None

def binary_search_hash(hash_list, target_hash):
    """Binary search trong sorted hash list"""
    # hash_list là list of tuples: (hash_string, sig_data)
    # Chỉ so sánh phần đầu (hash_string)
    idx = bisect.bisect_left([h[0] for h in hash_list], target_hash)
    if idx < len(hash_list) and hash_list[idx][0] == target_hash:
        return hash_list[idx][1]
    return None

def scan_file(file_path):
    """Scan file với virus signatures - tối ưu với binary search và Aho-Corasick"""
    results = {
        'detected': False,
        'threats': [],
        'file_info': {}
    }
    
    # Tính hash
    md5, sha256 = calculate_file_hash(file_path)
    results['file_info']['md5'] = md5
    results['file_info']['sha256'] = sha256
    
    # Bước 1: Kiểm tra hash với binary search
    md5_match = binary_search_hash(hash_signatures, md5.upper())
    if md5_match:
        results['detected'] = True
        results['threats'].append({
            'name': md5_match['name'],
            'type': md5_match['type'],
            'signature': 'MD5 Hash Match'
        })
    
    sha256_match = binary_search_hash(hash_signatures, sha256.upper())
    if sha256_match:
        results['detected'] = True
        results['threats'].append({
            'name': sha256_match['name'],
            'type': sha256_match['type'],
            'signature': 'SHA256 Hash Match'
        })
    
    # Bước 2: Scan patterns với Aho-Corasick hoặc fallback
    if not results['detected'] or len(results['threats']) < 50:
        # Đọc file content
        with open(file_path, 'rb') as f:
            file_content = f.read()
        
        if AHO_CORASICK_AVAILABLE and aho_automaton and pattern_map:
            # Sử dụng Aho-Corasick để tìm patterns
            # Convert file content sang hex string (Aho-Corasick cần string)
            file_hex = binascii.hexlify(file_content).decode('utf-8').upper()
            
            # iter() trả về (end_index, value) trong đó value là pattern hex string
            found_patterns = set()
            for end_index, pattern_hex in aho_automaton.iter(file_hex):
                # pattern_hex là hex string đã lưu khi add_word (value)
                if pattern_hex not in found_patterns and pattern_hex in pattern_map:
                    found_patterns.add(pattern_hex)
                    sig_data = pattern_map[pattern_hex]
                    results['detected'] = True
                    results['threats'].append({
                        'name': sig_data['name'],
                        'type': sig_data['type'],
                        'signature': sig_data['hex_signature'][:100] + '...' if len(sig_data['hex_signature']) > 100 else sig_data['hex_signature']
                    })
                    
                    if len(results['threats']) >= 50:
                        break
        else:
            # Fallback: scan từng pattern (chậm hơn)
            file_hex = binascii.hexlify(file_content).decode('utf-8').upper()
            for pattern, sig_data in pattern_signatures[:1000]:  # Giới hạn để không quá chậm
                if pattern in file_hex:
                    results['detected'] = True
                    results['threats'].append({
                        'name': sig_data['name'],
                        'type': sig_data['type'],
                        'signature': sig_data['hex_signature'][:100] + '...' if len(sig_data['hex_signature']) > 100 else sig_data['hex_signature']
                    })
                    
                    if len(results['threats']) >= 50:
                        break
    
    results['ml'] = None
    if predict_malware_cnn is not None:
        try:
            results['ml'] = predict_malware_cnn(str(file_path))
        except Exception as e:
            results['ml'] = {'available': False, 'error': str(e)}
    
    return results

@app.route('/')
def index():
    """Trang chủ"""
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    """API endpoint để upload và scan file"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if file and allowed_file(file.filename):
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        try:
            # Scan file
            results = scan_file(filepath)
            results['file_info']['filename'] = filename
            results['file_info']['size'] = os.path.getsize(filepath)
            
            # Xóa file sau khi scan (tùy chọn)
            # os.remove(filepath)
            
            return jsonify(results)
        except Exception as e:
            return jsonify({'error': str(e)}), 500
    
    return jsonify({'error': 'File type not allowed'}), 400

@app.route('/health')
def health():
    """Health check endpoint"""
    ml_path = str(ML_MODEL_PATH) if ML_MODEL_PATH else None
    ml_exists = ML_MODEL_PATH.is_file() if ML_MODEL_PATH else False
    return jsonify({
        'status': 'ok',
        'signatures_loaded': signatures_loaded,
        'signatures_count': len(virus_signatures),
        'ml_model_path': ml_path,
        'ml_model_available': ml_exists,
    })

if __name__ == '__main__':
    # Load signatures khi start server
    load_signatures()
    
    # Kiểm tra port từ environment variable hoặc dùng port 8080 mặc định
    port = int(os.environ.get('PORT', 8080))
    
    print(f"\n{'='*50}")
    print("VirusTotal-like Scanner")
    print(f"{'='*50}")
    print(f"Loaded {len(virus_signatures)} virus signatures")
    print(f"Server starting on http://127.0.0.1:{port}")
    print(f"{'='*50}\n")
    
    app.run(debug=True, host='0.0.0.0', port=port)
