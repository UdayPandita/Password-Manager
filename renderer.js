
const addressBar = document.getElementById('address-bar');
const goBtn = document.getElementById('go-btn');
const backBtn = document.getElementById('back-btn');
const fwdBtn = document.getElementById('fwd-btn');
const reloadBtn = document.getElementById('reload-btn');
const extBtn = document.getElementById('ext-btn');
const loadingIndicator = document.getElementById('loading-indicator');

let isLoading = false;
let loadingTimeout = null;

function showLoading() {
    if (!isLoading) {
        isLoading = true;
        loadingIndicator.classList.add('active');
        
        if (loadingTimeout) {
            clearTimeout(loadingTimeout);
        }
        
        loadingTimeout = setTimeout(() => {
            hideLoading();
        }, 10000);
    }
}

function hideLoading() {
    if (isLoading) {
        isLoading = false;
        loadingIndicator.classList.remove('active');
        
        if (loadingTimeout) {
            clearTimeout(loadingTimeout);
            loadingTimeout = null;
        }
        
        setTimeout(() => {
            if (!isLoading) {
                loadingIndicator.style.transform = 'scaleX(0)';
            }
        }, 300);
    }
}

function navigateToUrl() {
    const url = addressBar.value.trim();
    if (url) {
        showLoading();
        window.api.send('load-url', url);
    }
}

goBtn.addEventListener('click', navigateToUrl);

addressBar.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') {
        navigateToUrl();
    }
});

document.addEventListener('keydown', (e) => {
    if (e.ctrlKey && e.key === 'l') {
        e.preventDefault();
        addressBar.select();
    }
});

backBtn.addEventListener('click', () => {
    showLoading();
    window.api.send('go-back');
});

fwdBtn.addEventListener('click', () => {
    showLoading();
    window.api.send('go-forward');
});

reloadBtn.addEventListener('click', () => {
    showLoading();
    window.api.send('reload');
});

extBtn.addEventListener('click', () => {
    window.api.send('open-ext-popup');
});

window.api.receive('url-updated', (url) => {
    addressBar.value = url;
    hideLoading();
});

addressBar.addEventListener('focus', () => {
    addressBar.select();
});
