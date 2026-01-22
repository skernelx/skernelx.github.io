// --- Configuration (Generated) ---
// This token is encrypted with the user's password.
// It is NOT safe to decrypt without the password.
const appConfig = {
    "encryptedToken": "70429a029a209a4a5bfb274b77a5d527565cf7bb25e9c00f6ff80bb3387fe7ade97c32738ada0caf",
    "salt": "6278fd5ffed3a25c925b7d70fac1c771",
    "iv": "b1c7a251bedf6cddc4cdeff9",
    "authTag": "e6d3cb2d8bacd356d51ca67e2af4b6a6",
    "repoOwner": "skernelx",
    "repoName": "skernelx.github.io"
};

// --- Crypto Logic (Web Crypto API) ---

async function getDerivedKey(password, saltHex) {
    const enc = new TextEncoder();
    const keyMaterial = await window.crypto.subtle.importKey(
        "raw",
        enc.encode(password),
        { name: "PBKDF2" },
        false,
        ["deriveKey"]
    );

    const salt = hexToBuf(saltHex);
    return window.crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: salt,
            iterations: 100000,
            hash: "SHA-256"
        },
        keyMaterial,
        { name: "AES-GCM", length: 256 },
        false,
        ["decrypt"]
    );
}

async function decryptToken(encryptedHex, key, ivHex, authTagHex) {
    const iv = hexToBuf(ivHex);
    // Node's cipher.final('hex') + authTag needed to be concatenated for Web Crypto?
    // Node's aes-256-gcm usually outputs ciphertext then authtag.
    // In my generation script I did: encrypted += cipher.final('hex'); const authTag... 
    // And stored them separately. Web Crypto expects ciphertext + tag appended for decrypt.

    const ciphertext = hexToBuf(encryptedHex);
    const tag = hexToBuf(authTagHex);

    // Concat ciphertext + tag
    const data = new Uint8Array(ciphertext.byteLength + tag.byteLength);
    data.set(new Uint8Array(ciphertext), 0);
    data.set(new Uint8Array(tag), ciphertext.byteLength);

    try {
        const decrypted = await window.crypto.subtle.decrypt(
            { name: "AES-GCM", iv: iv },
            key,
            data
        );
        return new TextDecoder().decode(decrypted);
    } catch (e) {
        throw new Error("密码错误");
    }
}

function hexToBuf(hex) {
    return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16)));
}

// --- App State ---
let githubToken = null;

// --- DOM Elements ---
const loginOverlay = document.getElementById('login-overlay');
const passwordInput = document.getElementById('password-input');
const loginBtn = document.getElementById('login-btn');
const loginError = document.getElementById('login-error');
const appContainer = document.getElementById('app-container');
const dropZone = document.getElementById('drop-zone');
const fileInput = document.getElementById('file-input');
const historyList = document.getElementById('history-list');
const logoutBtn = document.getElementById('logout-btn');

// --- Initialization ---

async function init() {
    const savedPassword = localStorage.getItem('antigravity_access_key');
    if (savedPassword) {
        if (await attemptLogin(savedPassword)) {
            return;
        } else {
            localStorage.removeItem('antigravity_access_key');
        }
    }
    loginOverlay.classList.add('active');

    if (!window.crypto || !window.crypto.subtle) {
        alert("为了安全起见，Antigravity/Skernelx 图床依赖加密API，该功能仅在 HTTPS 环境下可用。\n\n检测到当前环境不支持加密（可能是 HTTP 访问），请尝试使用 https://nashome.me 访问。");
        loginError.textContent = "环境不安全：无法加载加密模块 (HTTPS only)";
    }
}

async function attemptLogin(password) {
    try {
        const key = await getDerivedKey(password, appConfig.salt);
        const token = await decryptToken(appConfig.encryptedToken, key, appConfig.iv, appConfig.authTag);

        // Login success
        githubToken = token;
        localStorage.setItem('antigravity_access_key', password); // Store password for convenience, or store token in sessionStorage

        // Hide Login, Show App
        loginOverlay.classList.remove('active');
        appContainer.classList.remove('hidden');
        return true;
    } catch (e) {
        console.error(e);
        return false;
    }
}

// --- Event Listeners ---

loginBtn.addEventListener('click', async () => {
    const pwd = passwordInput.value;
    if (!pwd) return;

    loginBtn.textContent = "验证中...";
    const success = await attemptLogin(pwd);
    if (!success) {
        loginError.textContent = "密码错误";
        loginBtn.textContent = "解锁";
    }
});

passwordInput.addEventListener('keypress', (e) => {
    if (e.key === 'Enter') loginBtn.click();
});

logoutBtn.addEventListener('click', () => {
    localStorage.removeItem('antigravity_access_key');
    location.reload();
});

// Drag & Drop
dropZone.addEventListener('click', () => fileInput.click());
dropZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    dropZone.classList.add('dragover');
});
dropZone.addEventListener('dragleave', () => dropZone.classList.remove('dragover'));
dropZone.addEventListener('drop', (e) => {
    e.preventDefault();
    dropZone.classList.remove('dragover');
    if (e.dataTransfer.files.length) {
        handleFiles(e.dataTransfer.files);
    }
});
fileInput.addEventListener('change', (e) => {
    if (e.target.files.length) handleFiles(e.target.files);
});

// --- Upload Logic ---

async function handleFiles(files) {
    for (const file of files) {
        await uploadToGitHub(file);
    }
}

async function uploadToGitHub(file) {
    // UI State
    document.getElementById('uploading-state').classList.remove('hidden');
    document.querySelector('.upload-content').classList.add('hidden');

    try {
        const reader = new FileReader();
        reader.readAsDataURL(file);
        reader.onload = async () => {
            const base64Content = reader.result.split(',')[1];

            // Generate Path: date/filename
            const date = new Date();
            const year = date.getFullYear();
            const month = String(date.getMonth() + 1).padStart(2, '0');
            const day = String(date.getDate()).padStart(2, '0');
            const timestamp = date.getTime();
            const ext = file.name.split('.').pop();
            const path = `images/${year}/${month}/${day}/${timestamp}.${ext}`;

            const url = `https://api.github.com/repos/${appConfig.repoOwner}/${appConfig.repoName}/contents/${path}`;

            const response = await fetch(url, {
                method: 'PUT',
                headers: {
                    'Authorization': `token ${githubToken}`,
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    message: `通过 Skernelx 图床上传 ${file.name}`,
                    content: base64Content
                })
            });

            if (!response.ok) throw new Error('上传失败');

            const data = await response.json();
            // Construct CDN URL (using jsDelivr or raw GitHub Pages link)
            // GitHub Pages Link: https://nashome.me/path
            const cdnUrl = `https://${appConfig.repoName === 'skernelx.github.io' ? 'nashome.me' : 'nashome.me'}/${path}`;

            addToHistory(file, cdnUrl);
        };
    } catch (e) {
        alert('上传失败: ' + e.message);
    } finally {
        document.getElementById('uploading-state').classList.add('hidden');
        document.querySelector('.upload-content').classList.remove('hidden');
    }
}

function addToHistory(file, url) {
    const div = document.createElement('div');
    div.className = 'history-item';
    div.innerHTML = `
        <div class="thumb" style="background-image: url(${url}); background-size: cover;"></div>
        <div class="info">
            <div class="filename">${file.name}</div>
            <div class="url">${url}</div>
        </div>
        <button class="copy-btn">复制</button>
    `;

    div.querySelector('.copy-btn').addEventListener('click', function () {
        navigator.clipboard.writeText(url);
        this.textContent = '已复制!';
        setTimeout(() => this.textContent = '复制', 2000);
    });

    // Add to top
    historyList.insertBefore(div, historyList.firstChild);
}

// Start
init();
