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

const COMPARE_STORAGE_KEY = 'virus_scan_compare_baseline_v1';

const ALLOWED_EXT_FOLDER = new Set([
    'txt',
    'pdf',
    'doc',
    'docx',
    'xls',
    'xlsx',
    'exe',
    'dll',
    'zip',
    'rar',
    '7z',
    'jpg',
    'jpeg',
    'png',
    'gif',
    'html',
    'htm',
    'js',
    'php',
    'py',
]);

const MAX_FOLDER_FILES = 120;

let scanProgressTimer = null;

function wantsVirustotal() {
    const chk = document.getElementById('chkVirusTotal');
    return !!(chk && chk.checked && !chk.disabled);
}

function folderFileAllowed(file) {
    const name = (file && file.name) || '';
    const base = name.replace(/\\/g, '/').split('/').pop() || '';
    const dot = base.lastIndexOf('.');
    if (dot < 0) return false;
    return ALLOWED_EXT_FOLDER.has(base.slice(dot + 1).toLowerCase());
}

function vtCategoryLabelVi(cat, result) {
    if (result) return result;
    const c = (cat || '').toLowerCase();
    if (c === 'undetected') return 'Undetected';
    if (c === 'harmless') return 'Harmless';
    if (c === 'timeout') return 'Timeout';
    if (c === 'failure') return 'Lỗi engine';
    if (c === 'type-unsupported') return 'Không hỗ trợ loại file';
    return cat || '—';
}

function vtEngineRowClass(cat) {
    const c = (cat || '').toLowerCase();
    if (c === 'malicious' || c === 'suspicious') return 'vt-eng-bad';
    if (c === 'undetected' || c === 'harmless') return 'vt-eng-ok';
    return 'vt-eng-muted';
}

function renderVirustotal(v) {
    const card = document.getElementById('vtCard');
    const body = document.getElementById('vtBody');
    if (!card || !body) return;
    if (v == null) {
        card.style.display = 'none';
        card.classList.remove('vt-card--dashboard');
        return;
    }
    card.style.display = 'block';
    if (v.configured === false) {
        card.classList.remove('vt-card--dashboard');
        body.innerHTML = '<p class="vt-msg">' + escapeHtml(v.message || 'Chưa cấu hình VirusTotal API key.') + '</p>';
        return;
    }
    if (v.not_found) {
        card.classList.remove('vt-card--dashboard');
        body.innerHTML = '<p class="vt-msg">' + escapeHtml(v.message || 'Chưa có trên VirusTotal.') + '</p>';
        return;
    }
    if (v.available === false && v.error) {
        card.classList.remove('vt-card--dashboard');
        body.innerHTML = '<p class="vt-msg vt-warn">' + escapeHtml(v.message || v.error) + '</p>';
        return;
    }
    if (v.available && v.stats) {
        card.classList.add('vt-card--dashboard');
        const s = v.stats;
        const mal = s.malicious || 0;
        const sus = s.suspicious || 0;
        const harm = s.harmless || 0;
        const und = s.undetected || 0;
        const badTotal = mal + sus;
        const engList = Array.isArray(v.engine_results) ? v.engine_results : [];
        const nEng = engList.length || v.engines_reported || 0;
        const link = v.permalink
            ? '<a class="vt-permalink" href="' + escapeHtml(v.permalink) + '" target="_blank" rel="noopener noreferrer">Mở báo cáo đầy đủ trên VirusTotal ↗</a>'
            : '';

        let metaBits = [];
        if (v.lookup_via === 'md5') {
            metaBits.push(
                '<span class="vt-lookup-note">Khớp qua <strong>MD5</strong> (SHA256 chưa có sẵn trên VT hoặc đã thử cả hai).</span>'
            );
        }
        if (v.meaningful_name) metaBits.push('<strong>' + escapeHtml(v.meaningful_name) + '</strong>');
        if (typeof v.size === 'number' && v.size >= 0) metaBits.push('Kích thước: ' + escapeHtml(formatFileSize(v.size)));
        if (v.type_description) metaBits.push(escapeHtml(v.type_description));
        const tags = Array.isArray(v.tags) && v.tags.length
            ? '<div class="vt-tags">' +
              v.tags.map((t) => '<span class="vt-tag">' + escapeHtml(t) + '</span>').join('') +
              '</div>'
            : '';

        let grid = '';
        if (engList.length === 0) {
            grid =
                '<p class="vt-engines-hint">API không trả về danh sách engine chi tiết cho mẫu này.</p>';
        } else {
            grid = '<div class="vt-engine-grid">';
            for (let i = 0; i < engList.length; i++) {
                const e = engList[i];
                const rowCls = vtEngineRowClass(e.category);
                const verdict = vtCategoryLabelVi(e.category, e.result);
                grid +=
                    '<div class="vt-engine-row ' +
                    rowCls +
                    '">' +
                    '<span class="vt-engine-name">' +
                    escapeHtml(e.engine) +
                    '</span>' +
                    '<span class="vt-engine-verdict">' +
                    escapeHtml(verdict) +
                    '</span></div>';
            }
            grid += '</div>';
        }

        body.innerHTML =
            '<div class="vt-dash">' +
            '<div class="vt-dash-header">' +
            '<div class="vt-score-block" title="Số engine gắn nhãn độc hại hoặc nghi ngờ">' +
            '<span class="vt-score-num">' +
            badTotal +
            '</span>' +
            '<span class="vt-score-denom">/ ' +
            nEng +
            '</span>' +
            '<div class="vt-score-caption">engine báo độc hại · nghi ngờ</div></div>' +
            '<div class="vt-dash-summary">' +
            '<div class="vt-mini-stats">' +
            '<span class="vt-ms vt-ms-bad">' +
            mal +
            ' độc hại</span> · ' +
            '<span class="vt-ms vt-ms-warn">' +
            sus +
            ' nghi ngờ</span> · ' +
            '<span class="vt-ms">' +
            und +
            ' không phát hiện</span> · ' +
            '<span class="vt-ms vt-ms-ok">' +
            harm +
            ' lành</span>' +
            '</div>' +
            (metaBits.length ? '<p class="vt-dash-meta">' + metaBits.join(' · ') + '</p>' : '') +
            tags +
            '<p class="vt-dash-link">' +
            link +
            '</p></div></div>' +
            '<h4 class="vt-engines-title">Phân tích từng engine</h4>' +
            '<p class="vt-engines-hint">Dữ liệu từ VirusTotal API (last_analysis_results). Giao diện gọn hơn trang chủ VT.</p>' +
            grid +
            '</div>';
        return;
    }
    card.classList.remove('vt-card--dashboard');
    body.innerHTML = '<p class="vt-msg">Không có dữ liệu VirusTotal.</p>';
}

function formatVtShort(v) {
    if (v == null) return '—';
    if (v.configured === false) return 'Chưa cấu key';
    if (v.not_found) return 'Chưa có VT';
    if (v.available === false) return v.error === 'rate_limited' ? '429' : 'Lỗi';
    if (v.available && v.stats) {
        const m = v.stats.malicious || 0;
        const s = v.stats.suspicious || 0;
        const t = v.engines_reported;
        if (t) return m + s + '/' + t + ' engine';
        return m + ' độc hại · ' + s + ' nghi ngờ';
    }
    return '—';
}

function formatMlShort(ml) {
    if (ml == null) return '—';
    if (ml.skipped) return 'Bỏ qua (nhanh)';
    if (!ml.available) return 'Không có';
    if (ml.mode === 'malimg_cridin1') {
        return (ml.is_benign_prediction ? 'Benign' : ml.predicted_class) || '—';
    }
    if (ml.label) return ml.label;
    return '—';
}

function displayFolderResults(rows) {
    const section = document.getElementById('batchResultsSection');
    const tbody = document.getElementById('batchTableBody');
    const summary = document.getElementById('batchSummary');
    if (!section || !tbody) return;
    tbody.innerHTML = '';
    let ok = 0;
    let clam = 0;
    for (const row of rows) {
        const tr = document.createElement('tr');
        if (row.error) {
            tr.innerHTML =
                '<td class="batch-path">' +
                escapeHtml(row.path || '-') +
                '</td><td colspan="3" class="vt-warn">' +
                escapeHtml(row.error) +
                '</td>';
        } else {
            const d = row.data;
            ok++;
            if (d.detected) clam++;
            const path = (d.file_info && d.file_info.filename) || '-';
            const c = d.detected
                ? '<span class="batch-flag-yes">Có (' + (d.threats ? d.threats.length : 0) + ')</span>'
                : '<span class="batch-flag-no">Không</span>';
            const vt = formatVtShort(d.virustotal);
            const ml = formatMlShort(d.ml);
            const mlCls = d.ml && d.ml.skipped ? 'batch-flag-skip' : '';
            tr.innerHTML =
                '<td class="batch-path">' +
                escapeHtml(path) +
                '</td><td>' +
                c +
                '</td><td>' +
                escapeHtml(vt) +
                '</td><td class="' +
                mlCls +
                '">' +
                escapeHtml(ml) +
                '</td>';
        }
        tbody.appendChild(tr);
    }
    if (summary) {
        summary.textContent =
            'Đã xử lý ' +
            rows.length +
            ' mục (' +
            ok +
            ' thành công). ClamAV phát hiện: ' +
            clam +
            ' file.';
    }
    section.style.display = 'block';
    document.getElementById('resultsSection').style.display = 'none';
    document.getElementById('uploadSection').style.display = 'none';
}

async function runFolderScan(fileList) {
    const maxSize = 100 * 1024 * 1024;
    const eligible = [];
    const arr = Array.from(fileList);
    for (const f of arr) {
        if (!folderFileAllowed(f)) continue;
        if (f.size > maxSize) continue;
        eligible.push(f);
        if (eligible.length >= MAX_FOLDER_FILES) break;
    }
    if (eligible.length === 0) {
        alert('Không có file hợp lệ (đuôi cho phép như trên server, dung lượng ≤ 100MB).');
        return;
    }
    const fullMlEl = document.getElementById('chkFolderFullMl');
    const light = !(fullMlEl && fullMlEl.checked);
    const vt = wantsVirustotal();
    if (vt && eligible.length > 12) {
        if (
            !confirm(
                'Bạn đang bật VirusTotal cho ' +
                    eligible.length +
                    ' file — dễ vượt hạn mức API. Tiếp tục?'
            )
        ) {
            return;
        }
    }

    document.getElementById('batchResultsSection').style.display = 'none';
    document.getElementById('resultsSection').style.display = 'none';
    loadingOverlay.style.display = 'flex';
    uploadSection.style.display = 'none';
    startScanProgress();

    const rows = [];
    for (let i = 0; i < eligible.length; i++) {
        const f = eligible[i];
        const lt = document.getElementById('loadingTitle');
        if (lt) {
            lt.textContent = 'Thư mục: ' + (i + 1) + '/' + eligible.length + ' — ' + f.name;
        }
        const fd = new FormData();
        fd.append('file', f);
        const rel = f.webkitRelativePath || f.name;
        fd.append('display_name', rel);
        if (light) fd.append('light', '1');
        if (vt) fd.append('virustotal', '1');
        try {
            const res = await fetch('/upload', { method: 'POST', body: fd });
            const data = await res.json();
            if (data.error) {
                rows.push({ error: data.error, path: rel });
            } else {
                rows.push({ data: data });
            }
        } catch (err) {
            rows.push({ error: err.message || String(err), path: rel });
        }
    }
    hideLoading();
    displayFolderResults(rows);
    const fi = document.getElementById('folderInput');
    if (fi) fi.value = '';
}

function resetScanStepsUI() {
    document.querySelectorAll('#scanSteps .scan-step').forEach((el) => {
        el.classList.remove('active', 'done');
    });
}

function setScanStepActive(index) {
    const items = document.querySelectorAll('#scanSteps .scan-step');
    items.forEach((el, i) => {
        el.classList.toggle('active', i === index);
        el.classList.toggle('done', i < index);
    });
}

function completeScanStepsUI() {
    document.querySelectorAll('#scanSteps .scan-step').forEach((el) => {
        el.classList.remove('active');
        el.classList.add('done');
    });
}

function startScanProgress() {
    resetScanStepsUI();
    setScanStepActive(0);
    let step = 0;
    if (scanProgressTimer) clearInterval(scanProgressTimer);
    scanProgressTimer = setInterval(() => {
        step = Math.min(step + 1, 2);
        setScanStepActive(step);
    }, 650);
}

function stopScanProgress() {
    if (scanProgressTimer) {
        clearInterval(scanProgressTimer);
        scanProgressTimer = null;
    }
    completeScanStepsUI();
}

function summarizeScanPayload(data) {
    return {
        filename: (data.file_info && data.file_info.filename) || '-',
        md5: (data.file_info && data.file_info.md5) || null,
        detected: !!data.detected,
        threatCount: data.threats ? data.threats.length : 0,
        firstThreat: data.threats && data.threats[0] ? data.threats[0].name : null,
        mlAvailable: !!(data.ml && data.ml.available),
        mlMode: data.ml && data.ml.mode,
        predicted_class: data.ml && data.ml.predicted_class,
        benign_probability: data.ml && typeof data.ml.benign_probability === 'number' ? data.ml.benign_probability : null,
        is_benign_prediction: !!(data.ml && data.ml.is_benign_prediction),
        mlLabel: data.ml && data.ml.label,
    };
}

function updateCompareChrome() {
    const raw = sessionStorage.getItem(COMPARE_STORAGE_KEY);
    const btnClear = document.getElementById('btnClearCompare');
    if (btnClear) {
        btnClear.style.display = raw ? 'inline-block' : 'none';
    }
}

function renderMlTop5Bars(container, items) {
    if (!container || !items || !items.length) return;
    const maxP = Math.max(...items.map((x) => x.probability), 1e-9);
    container.innerHTML = '';
    items.forEach((item, i) => {
        const row = document.createElement('div');
        row.className = 'ml-top5-bar-row';
        const pct = (item.probability * 100).toFixed(2);
        const widthPct = (item.probability / maxP) * 100;
        row.innerHTML =
            '<div class="ml-top5-bar-label">' +
            '<span class="ml-top5-rank">' +
            (i + 1) +
            '</span>' +
            '<span class="ml-top5-name">' +
            escapeHtml(item.class) +
            '</span>' +
            '<span class="ml-top5-pct">' +
            pct +
            '%</span></div>' +
            '<div class="ml-top5-bar-track"><div class="ml-top5-bar-fill" style="width:0%"></div></div>';
        container.appendChild(row);
        const fill = row.querySelector('.ml-top5-bar-fill');
        requestAnimationFrame(() => {
            if (fill) fill.style.width = widthPct + '%';
        });
    });
}

function renderCompareSection(data) {
    const card = document.getElementById('compareCard');
    const grid = document.getElementById('compareGrid');
    const raw = sessionStorage.getItem(COMPARE_STORAGE_KEY);
    updateCompareChrome();
    if (!card || !grid || !raw) {
        if (card) card.style.display = 'none';
        return;
    }
    let baseline;
    try {
        baseline = JSON.parse(raw);
    } catch (e) {
        card.style.display = 'none';
        return;
    }
    const cur = summarizeScanPayload(data);
    card.style.display = 'block';

    if (baseline.md5 && cur.md5 && baseline.md5 === cur.md5) {
        grid.innerHTML =
            '<p class="compare-same">Đây vẫn là cùng file (MD5 trùng). Quét <strong>file khác</strong> để xem bảng so sánh ClamAV + AI.</p>';
        return;
    }

    const clamA = baseline.detected
        ? 'Có — ' + baseline.threatCount + ' khớp' + (baseline.firstThreat ? ' (' + escapeHtml(baseline.firstThreat) + '…)' : '')
        : 'Không';
    const clamB = cur.detected
        ? 'Có — ' + cur.threatCount + ' khớp' + (cur.firstThreat ? ' (' + escapeHtml(cur.firstThreat) + '…)' : '')
        : 'Không';

    let aiA = '—';
    if (baseline.mlAvailable) {
        if (baseline.mlMode === 'malimg_cridin1') {
            const pb =
                baseline.benign_probability != null
                    ? (Math.round(baseline.benign_probability * 1000) / 10).toFixed(1)
                    : '?';
            aiA =
                (baseline.is_benign_prediction ? 'Top-1: Benign' : 'Top-1: ' + escapeHtml(baseline.predicted_class || '-')) +
                ' · P(Benign) ' +
                pb +
                '%';
        } else {
            aiA = 'Legacy: ' + escapeHtml(baseline.mlLabel || '-') + '';
        }
    } else {
        aiA = 'Không chạy / chưa có model';
    }

    let aiB = '—';
    if (cur.mlAvailable) {
        if (cur.mlMode === 'malimg_cridin1') {
            const pb =
                cur.benign_probability != null ? (Math.round(cur.benign_probability * 1000) / 10).toFixed(1) : '?';
            aiB =
                (cur.is_benign_prediction ? 'Top-1: Benign' : 'Top-1: ' + escapeHtml(cur.predicted_class || '-')) +
                ' · P(Benign) ' +
                pb +
                '%';
        } else {
            aiB = 'Legacy: ' + escapeHtml(cur.mlLabel || '-') + '';
        }
    } else {
        aiB = 'Không chạy / chưa có model';
    }

    grid.innerHTML =
        '<div class="compare-col compare-col-baseline">' +
        '<div class="compare-col-title">Mốc đã lưu</div>' +
        '<div class="compare-field"><span class="compare-k">File</span><span class="compare-v">' +
        escapeHtml(baseline.filename) +
        '</span></div>' +
        '<div class="compare-field"><span class="compare-k">ClamAV</span><span class="compare-v">' +
        clamA +
        '</span></div>' +
        '<div class="compare-field"><span class="compare-k">AI</span><span class="compare-v">' +
        aiA +
        '</span></div>' +
        '</div>' +
        '<div class="compare-col compare-col-current">' +
        '<div class="compare-col-title">Lần quét này</div>' +
        '<div class="compare-field"><span class="compare-k">File</span><span class="compare-v">' +
        escapeHtml(cur.filename) +
        '</span></div>' +
        '<div class="compare-field"><span class="compare-k">ClamAV</span><span class="compare-v">' +
        clamB +
        '</span></div>' +
        '<div class="compare-field"><span class="compare-k">AI</span><span class="compare-v">' +
        aiB +
        '</span></div>' +
        '</div>';
}

function saveCompareBaseline() {
    if (!window.__lastScanResult) return;
    sessionStorage.setItem(COMPARE_STORAGE_KEY, JSON.stringify(summarizeScanPayload(window.__lastScanResult)));
    updateCompareChrome();
    renderCompareSection(window.__lastScanResult);
}

function clearCompareBaseline() {
    sessionStorage.removeItem(COMPARE_STORAGE_KEY);
    updateCompareChrome();
    const card = document.getElementById('compareCard');
    if (card) card.style.display = 'none';
    if (window.__lastScanResult) renderCompareSection(window.__lastScanResult);
}

// Load signature count + model metadata on page load
window.addEventListener('DOMContentLoaded', () => {
    fetch('/health')
        .then((res) => res.json())
        .then((data) => {
            const countEl = document.getElementById('signatureCount');
            if (countEl) {
                countEl.textContent = data.signatures_count.toLocaleString();
            }
            const footMeta = document.getElementById('mlFooterMeta');
            if (footMeta) {
                let extra = '';
                if (data.ml_model_available) {
                    const kindLabel =
                        data.ml_model_kind === 'malimg_softmax'
                            ? 'Malimg + softmax'
                            : data.ml_model_kind === 'legacy_binary'
                              ? 'CNN nhị phân (legacy)'
                              : 'AI';
                    const nClass =
                        typeof data.ml_num_classes === 'number' ? ' · ' + data.ml_num_classes + ' lớp (metadata)' : '';
                    extra = ' | Model: ' + kindLabel + nClass + ' · tham chiếu cridin1 / readme-ml.md';
                } else {
                    extra = ' | AI: chưa có model — xem readme-ml.md, lệnh python train_cnn.py';
                }
                extra += data.virustotal_configured
                    ? ' | VirusTotal: đã cấu hình key'
                    : ' | VirusTotal: chưa có VIRUSTOTAL_API_KEY';
                footMeta.textContent = extra;
            }
            const chkVt = document.getElementById('chkVirusTotal');
            const vtHint = document.getElementById('vtHint');
            if (chkVt) {
                if (data.virustotal_configured) {
                    chkVt.disabled = false;
                    chkVt.title = '';
                } else {
                    chkVt.disabled = true;
                    chkVt.checked = false;
                    chkVt.title = 'Đặt biến môi trường VIRUSTOTAL_API_KEY rồi khởi động lại server.';
                }
            }
            if (vtHint && !data.virustotal_configured) {
                vtHint.style.opacity = '0.95';
            }
            updateCompareChrome();
        })
        .catch((err) => console.error('Error loading health:', err));
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
    if (e.target.tagName !== 'BUTTON' && e.target.tagName !== 'INPUT' && !e.target.closest('button')) {
        fileInput.click();
    }
});

// File input change handler
fileInput.addEventListener(
    'change',
    (e) => {
        const file = e.target.files && e.target.files[0];
        if (file) {
            handleFile(file);
        }
    },
    false
);

const folderInput = document.getElementById('folderInput');
const btnPickFolder = document.getElementById('btnPickFolder');
if (btnPickFolder && folderInput) {
    btnPickFolder.addEventListener('click', (e) => {
        e.stopPropagation();
        e.preventDefault();
        folderInput.click();
    });
}
if (folderInput) {
    folderInput.addEventListener('change', (e) => {
        const files = e.target.files;
        if (files && files.length) {
            runFolderScan(files);
        }
    });
}

function handleFile(file) {
    const maxSize = 100 * 1024 * 1024;
    if (file.size > maxSize) {
        alert('File quá lớn! Kích thước tối đa là 100MB.');
        return;
    }

    showLoading();

    const formData = new FormData();
    formData.append('file', file);
    if (wantsVirustotal()) {
        formData.append('virustotal', '1');
    }

    fetch('/upload', {
        method: 'POST',
        body: formData,
    })
        .then((response) => response.json())
        .then((data) => {
            hideLoading();
            displayResults(data);
        })
        .catch((error) => {
            hideLoading();
            alert('Lỗi khi quét file: ' + error.message);
            console.error('Error:', error);
        });
}

function showLoading() {
    startScanProgress();
    loadingOverlay.style.display = 'flex';
    uploadSection.style.display = 'none';
    resultsSection.style.display = 'none';
    const batchEl = document.getElementById('batchResultsSection');
    if (batchEl) batchEl.style.display = 'none';
    const lt = document.getElementById('loadingTitle');
    if (lt) lt.textContent = 'Đang xử lý…';
}

function hideLoading() {
    stopScanProgress();
    loadingOverlay.style.display = 'none';
}

function displayResults(data) {
    window.__lastScanResult = data;
    uploadSection.style.display = 'none';
    resultsSection.style.display = 'block';
    const batchSec = document.getElementById('batchResultsSection');
    if (batchSec) batchSec.style.display = 'none';

    const prevCard = document.getElementById('malimgPreviewCard');
    const prevImg = document.getElementById('malimgPreviewImg');
    if (data.malimg_preview_png_base64 && prevCard && prevImg) {
        prevCard.style.display = 'block';
        prevImg.src = 'data:image/png;base64,' + data.malimg_preview_png_base64;
    } else if (prevCard) {
        prevCard.style.display = 'none';
    }

    document.getElementById('fileName').textContent = data.file_info.filename || '-';
    document.getElementById('fileSize').textContent = formatFileSize(data.file_info.size || 0);
    document.getElementById('fileMD5').textContent = data.file_info.md5 || '-';
    document.getElementById('fileSHA256').textContent = data.file_info.sha256 || '-';

    renderVirustotal(data.virustotal);

    const mlCard = document.getElementById('mlCard');
    const mlHint = document.getElementById('mlHint');
    const mlBarWrap = document.getElementById('mlBarWrap');
    const mlProbPct = document.getElementById('mlProbPct');
    const mlBarFill = document.getElementById('mlBarFill');
    const mlTop5Wrap = document.getElementById('mlTop5Wrap');
    const mlTop5Bars = document.getElementById('mlTop5Bars');
    const mlVerdict = document.getElementById('mlVerdict');
    const mlBadge = document.getElementById('mlBadge');
    const mlVerdictText = document.getElementById('mlVerdictText');
    const mlStatBenign = document.getElementById('mlStatBenign');

    function hideMlExtras() {
        if (mlVerdict) mlVerdict.style.display = 'none';
        if (mlStatBenign) mlStatBenign.style.display = 'none';
        if (mlTop5Wrap) mlTop5Wrap.style.display = 'none';
        if (mlTop5Bars) mlTop5Bars.innerHTML = '';
        if (mlBarWrap) mlBarWrap.style.display = 'none';
    }

    if (data.ml != null && data.ml.skipped && mlCard) {
        mlCard.style.display = 'none';
    } else if (data.ml != null && mlCard) {
        mlCard.style.display = 'block';
        if (!data.ml.available) {
            hideMlExtras();
            mlHint.textContent =
                data.ml.message ||
                data.ml.error ||
                'Chưa cấu hình model AI. Trong thư mục web, chạy train hoặc đặt file malimg_model.keras (xem readme-ml.md).';
        } else if (data.ml.mode === 'malimg_cridin1') {
            const pred = data.ml.predicted_class || '-';
            const benign = data.ml.is_benign_prediction;
            const pBenign =
                typeof data.ml.benign_probability === 'number' ? Math.round(data.ml.benign_probability * 1000) / 10 : null;

            if (mlVerdict && mlBadge && mlVerdictText) {
                mlVerdict.style.display = 'flex';
                mlBadge.className = 'ml-badge' + (benign ? ' ml-badge-safe' : ' ml-badge-warn');
                mlBadge.textContent = benign ? 'Nhóm sạch (Benign) đứng đầu' : 'Ưu tiên xem xét thêm';
                mlVerdictText.textContent = benign
                    ? 'Trong các nhãn mô hình được huấn luyện, nhãn sạch (Benign) đang có xác suất cao nhất. Vẫn nên đối chiếu với kết quả chữ ký phía trên.'
                    : `Nhãn được chọn cao nhất hiện là "${pred}" (tên họ / loại trong bộ dữ liệu Malimg). Đây chỉ là gợi ý phân loại, không phải tên virus từ ClamAV.`;
            }

            mlHint.textContent =
                'Cách hoạt động (rút gọn): file được biến thành ảnh theo phương pháp Malimg, rồi đưa qua mạng nơ-ron. Chi tiết trong readme-ml.md.';

            if (mlStatBenign && pBenign != null) {
                mlStatBenign.style.display = 'block';
                mlStatBenign.innerHTML =
                    'Độ tin <strong>file sạch</strong> (nhãn Benign): <strong>' + pBenign + '%</strong>. Phần còn lại được chia cho các nhãn khác — đó là lý do các dòng bên dưới thường có % nhỏ.';
            } else if (mlStatBenign) {
                mlStatBenign.style.display = 'none';
            }

            if (mlTop5Wrap && mlTop5Bars && Array.isArray(data.ml.probabilities_top5)) {
                mlTop5Wrap.style.display = 'block';
                renderMlTop5Bars(mlTop5Bars, data.ml.probabilities_top5);
            }

            const p = typeof data.ml.malware_probability === 'number' ? data.ml.malware_probability : 0;
            const pct = Math.round(p * 1000) / 10;
            mlBarWrap.style.display = 'block';
            mlProbPct.textContent = pct + '%';
            mlBarFill.style.width = Math.min(100, pct) + '%';
            mlBarFill.className = 'ml-bar-fill' + (!benign ? ' danger' : '');
        } else {
            if (mlVerdict && mlBadge && mlVerdictText) {
                mlVerdict.style.display = 'flex';
                const legacyMal = data.ml.label === 'malware';
                mlBadge.className = 'ml-badge' + (legacyMal ? ' ml-badge-warn' : ' ml-badge-safe');
                mlBadge.textContent = legacyMal ? 'Mô hình cũ: nghi ngờ' : 'Mô hình cũ: gần lành';
                mlVerdictText.textContent =
                    'Đang dùng model nhị phân cũ (một đầu ra), khác với bản Malimg 26 lớp. Nên huấn luyện malimg_model.keras để đồng bộ với tài liệu readme-ml.md.';
            }
            if (mlStatBenign) mlStatBenign.style.display = 'none';
            const p = data.ml.malware_probability;
            const pct = Math.round((typeof p === 'number' ? p : 0) * 1000) / 10;
            mlHint.textContent =
                data.ml.label === 'malware'
                    ? `Điểm “mã độc” do model cũ ước lượng: khoảng ${pct}%. Chỉ mang tính minh họa.`
                    : `Model cũ cho rằng file gần với nhóm lành hơn (điểm mã độc ~${pct}%).`;
            if (mlTop5Wrap) mlTop5Wrap.style.display = 'none';
            if (mlTop5Bars) mlTop5Bars.innerHTML = '';
            mlBarWrap.style.display = 'block';
            mlProbPct.textContent = pct + '%';
            mlBarFill.style.width = Math.min(100, pct) + '%';
            mlBarFill.className = 'ml-bar-fill' + (data.ml.label === 'malware' ? ' danger' : '');
        }
    } else if (mlCard) {
        mlCard.style.display = 'none';
    }

    if (data.detected) {
        statusIcon.className = 'status-icon danger';
        statusIcon.innerHTML = '⚠️';
        statusText.textContent = 'Mối đe dọa được phát hiện!';
        statusText.style.color = '#ef4444';
        statusSubtext.textContent = `Phát hiện ${data.threats.length} mối đe dọa`;

        threatsList.style.display = 'block';
        threatsContainer.innerHTML = '';

        data.threats.forEach((threat) => {
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
        statusIcon.className = 'status-icon safe';
        statusIcon.innerHTML = '✓';
        statusText.textContent = 'Không phát hiện mối đe dọa';
        statusText.style.color = '#10b981';
        statusSubtext.textContent = 'File này có vẻ an toàn';

        threatsList.style.display = 'none';
    }

    renderCompareSection(data);
}

function resetScan() {
    uploadSection.style.display = 'block';
    resultsSection.style.display = 'none';
    const batchEl = document.getElementById('batchResultsSection');
    if (batchEl) batchEl.style.display = 'none';
    fileInput.value = '';
    threatsContainer.innerHTML = '';
    threatsList.style.display = 'none';
    const mlCardReset = document.getElementById('mlCard');
    if (mlCardReset) mlCardReset.style.display = 'none';
    const prevCard = document.getElementById('malimgPreviewCard');
    if (prevCard) prevCard.style.display = 'none';
    const vtCard = document.getElementById('vtCard');
    if (vtCard) vtCard.style.display = 'none';
    const fi = document.getElementById('folderInput');
    if (fi) fi.value = '';
}

function formatFileSize(bytes) {
    if (bytes === 0) return '0 Bytes';
    const k = 1024;
    const sizes = ['Bytes', 'KB', 'MB', 'GB'];
    const i = Math.floor(Math.log(bytes) / Math.log(k));
    return Math.round((bytes / Math.pow(k, i)) * 100) / 100 + ' ' + sizes[i];
}

function escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text == null ? '' : String(text);
    return div.innerHTML;
}
