const { app, BrowserWindow, BrowserView, ipcMain, session } = require('electron');
const path = require('path');

let mainWindow;
let webView;
let extensionId = '';
let popupWindow;

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1200,
        height: 800,
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
        }
    });

    mainWindow.loadFile('index.html')
        .catch(err => console.error('Failed to load index.html', err));

    webView = new BrowserView();
    mainWindow.addBrowserView(webView);

    const extensionPath = path.join(__dirname, 'extension');

    session.defaultSession.loadExtension(extensionPath)
        .then(({ id }) => {
            extensionId = id; 
        })
        .catch(err => console.error('Error loading extension:', err));

    function updateViewBounds() {
        const [width, height] = mainWindow.getContentSize();
        webView.setBounds({ x: 0, y: 60, width: width, height: height - 60 });
    }

    updateViewBounds();
    mainWindow.on('resize', updateViewBounds);

    webView.webContents.loadURL('https://google.com')
        .catch(err => console.error('Failed to load default URL', err)); 

    webView.webContents.on('did-navigate', (event, url) => {
        mainWindow.webContents.send('url-updated', url);
    });
    
    webView.webContents.on('did-finish-load', () => {
        const url = webView.webContents.getURL();
        mainWindow.webContents.send('url-updated', url);
    });
}

app.whenReady().then(createWindow);

ipcMain.on('load-url', (event, url) => {
    if (!webView) return;
    let fullUrl = url;
    if (!url.startsWith('http')) {
        fullUrl = 'https://' + url;
    }
    webView.webContents.loadURL(fullUrl)
        .catch(err => console.error('Failed to load user URL', err)); 
});

ipcMain.on('go-back', () => {
    if (webView && webView.webContents.canGoBack()) {
        webView.webContents.goBack();
    }
});

ipcMain.on('go-forward', () => {
    if (webView && webView.webContents.canGoForward()) {
        webView.webContents.goForward();
    }
});

ipcMain.on('reload', () => {
    if (webView) {
        webView.webContents.reload();
    }
});

ipcMain.on('open-ext-popup', () => {
    if (!extensionId) {
        console.error("Extension ID is not set. Is the extension loaded?");
        return;
    }

    if (popupWindow && !popupWindow.isDestroyed()) {
        popupWindow.focus();
        return;
    }

    const popupUrl = `chrome-extension://${extensionId}/popup.html`;

    popupWindow = new BrowserWindow({
        width: 800,
        height: 600,
        frame: true,
        resizable: true,
        alwaysOnTop: false,
        webPreferences: {}
    });

    popupWindow.loadURL(popupUrl)
        .catch(err => console.error('Failed to load popup URL', err));

    popupWindow.on('closed', () => {
        popupWindow = null;
    });
});
