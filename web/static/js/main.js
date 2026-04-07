// DOM Elements
const fileInput = document.getElementById('fileInput');
const uploadBox = document.getElementById('uploadBox');
const uploadSection = document.getElementById('uploadSection');
const resultsSection = document.getElementById('resultsSection');
const loadingOverlay = document.getElementById('loadingOverlay');
const threatsList = document.getElementById('threatsList');
const threatsContainer = document.getElementById('threatsContainer');
const statusIcon = document.getElementById('statusIcon');
const statusText = document.getElementById('statusText');
const statusSubtext = document.getElementById('statusSubtext');

// Load signature count on page load
window.addEventListener('DOMContentLoaded', () => {
    fetch('/health')
        .then(res => res.json())
        .then(data => {
            const countEl = document.getElementById('signatureCount');
            if (countEl) {
                countEl.textContent = data.signatures_count.toLocaleString();
            }
            const foot = document.querySelector('footer p');
            if (foot && data.ml_model_available === false && !foot.dataset.mlHintAdded) {
                foot.dataset.mlHintAdded = '1';
                foot.insertAdjacentHTML(
                    'beforeend',
                    ' | CNN: chưa có model — <code>cd web && python train_cnn.py</code>'
                );
            }
        })
        .catch(err => console.error('Error loading health:', err));
});

// Drag and drop handlers
uploadBox.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadBox.classList.add('dragover');
});

uploadBox.addEventListener('dragleave', () => {
    uploadBox.classList.remove('dragover');
});

uploadBox.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadBox.classList.remove('dragover');
    
    const files = e.dataTransfer.files;
    if (files.length > 0) {
        handleFile(files[0]);
    }
});

// Click handler - trigger khi click vào uploadBox (trừ button)
uploadBox.addEventListener('click', (e) => {
    // Chỉ trigger nếu không phải click vào button hoặc input
    if (e.target.tagName !== 'BUTTON' && e.target.tagName !== 'INPUT' && !e.target.closest('button')) {
        fileInput.click();
    }
});

// File input change handler - xử lý ngay khi chọn file
fileInput.addEventListener('change', (e) => {
    const file = e.target.files && e.target.files[0];
    if (file) {
        handleFile(file);
    }
}, false);

function handleFile(file) {
    // Validate file size (100MB)
    const maxSize = 100 * 1024 * 1024;
    if (file.size > maxSize) {
        alert('File quá lớn! Kích thước tối đa là 100MB.');
        return;
    }
    
    // Show loading
    showLoading();
    
    // Upload and scan
    const formData = new FormData();
    formData.append('file', file);
    
    fetch('/upload', {
        method: 'POST',
        body: formData
    })
    .then(response => response.json())
    .then(data => {
        hideLoading();
        displayResults(data);
    })
    .catch(error => {
        hideLoading();
        alert('Lỗi khi quét file: ' + error.message);
        console.error('Error:', error);
    });
}

function showLoading() {
    loadingOverlay.style.display = 'flex';
    uploadSection.style.display = 'none';
    resultsSection.style.display = 'none';
}

function hideLoading() {
    loadingOverlay.style.display = 'none';
}

function displayResults(data) {
    // Show results section
    uploadSection.style.display = 'none';
    resultsSection.style.display = 'block';
    
    // Display file info
    document.getElementById('fileName').textContent = data.file_info.filename || '-';
    document.getElementById('fileSize').textContent = formatFileSize(data.file_info.size || 0);
    document.getElementById('fileMD5').textContent = data.file_info.md5 || '-';
    document.getElementById('fileSHA256').textContent = data.file_info.sha256 || '-';
    
    const mlCard = document.getElementById('mlCard');
    const mlHint = document.getElementById('mlHint');
    const mlBarWrap = document.getElementById('mlBarWrap');
    const mlProbPct = document.getElementById('mlProbPct');
    const mlBarFill = document.getElementById('mlBarFill');
    if (data.ml != null && mlCard) {
        mlCard.style.display = 'block';
        if (!data.ml.available) {
            mlHint.textContent = data.ml.message || data.ml.error || 'Model CNN chưa sẵn sàng.';
            mlBarWrap.style.display = 'none';
        } else {
            const p = data.ml.malware_probability;
            const pct = Math.round(p * 1000) / 10;
            mlHint.textContent =
                data.ml.label === 'malware'
                    ? `Model gán nhãn: có khả năng mã độc (${pct}% — chỉ tham khảo, cần train trên dữ liệu thật).`
                    : `Model gán nhãn: lành (${pct}% malware score — tham khảo).`;
            mlBarWrap.style.display = 'block';
            mlProbPct.textContent = pct + '%';
            mlBarFill.style.width = pct + '%';
            mlBarFill.className = 'ml-bar-fill' + (data.ml.label === 'malware' ? ' danger' : '');
        }
    } else if (mlCard) {
        mlCard.style.display = 'none';
    }

    // Display threat status
    if (data.detected) {
        // Threats detected
        statusIcon.className = 'status-icon danger';
        statusIcon.innerHTML = '⚠️';
        statusText.textContent = 'Mối đe dọa được phát hiện!';
        statusText.style.color = '#ef4444';
        statusSubtext.textContent = `Phát hiện ${data.threats.length} mối đe dọa`;
        
        // Display threats
        threatsList.style.display = 'block';
        threatsContainer.innerHTML = '';
        
        data.threats.forEach(threat => {
            const threatItem = document.createElement('div');
            threatItem.className = 'threat-item';
            threatItem.innerHTML = `
                <div class="threat-name">${escapeHtml(threat.name)}</div>
                <div class="threat-type">Type: ${threat.type}</div>
                <div class="threat-signature">Signature: ${escapeHtml(threat.signature)}</div>
            `;
            threatsContainer.appendChild(threatItem);
        });
    } else {
        // No threats
        statusIcon.className = 'status-icon safe';
        statusIcon.innerHTML = '✓';
        statusText.textContent = 'Không phát hiện mối đe dọa';
        statusText.style.color = '#10b981';
        statusSubtext.textContent = 'File này có vẻ an toàn';
        
        threatsList.style.display = 'none';
    }
}

function resetScan() {
    uploadSection.style.display = 'block';
    resultsSection.style.display = 'none';
    fileInput.value = '';
    threatsContainer.innerHTML = '';
    threatsList.style.display = 'none';
    const mlCardReset = document.getElementById('mlCard');
    if (mlCardReset) mlCardReset.style.display = 'none';
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}
