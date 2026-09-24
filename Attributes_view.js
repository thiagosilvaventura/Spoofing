/**
 * -----------------------------------------------------------------------------
 * DATA NECROMANCER
 * -----------------------------------------------------------------------------
 * This script extracts hardware, network, and browser identity attributes 
 * commonly used by advanced anti-fraud systems (like LexisNexis ThreatMetrix).
 * 
 * It bypasses TrustedHTML restrictions by using native DOM creation methods.
 * -----------------------------------------------------------------------------
 */

(async function runFingerprintExtractor() {
    // 1. Clean up any existing instance of the panel
    const existingPanel = document.getElementById('github-fp-training-panel');
    if (existingPanel) existingPanel.remove();

    // 2. Create the main floating panel
    const panel = document.createElement('div');
    panel.id = 'github-fp-training-panel';
    panel.style.cssText = `
        position: fixed; top: 20px; right: 20px; width: 420px; max-height: 90vh; overflow-y: auto;
        background: rgba(15, 23, 42, 0.95); backdrop-filter: blur(10px); -webkit-backdrop-filter: blur(10px);
        border: 1px solid #3b82f6; border-radius: 8px; z-index: 2147483647; padding: 20px;
        color: #e2e8f0; font-family: system-ui, -apple-system, sans-serif; box-shadow: 0 15px 40px rgba(0,0,0,0.8);
        box-sizing: border-box; text-align: left; line-height: 1.5;
    `;

    // 3. Create Header
    const header = document.createElement('div');
    header.style.cssText = 'display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid rgba(59, 130, 246, 0.3); padding-bottom: 10px; margin-bottom: 15px;';
    
    const title = document.createElement('h2');
    title.style.cssText = 'margin: 0; color: #3b82f6; font-size: 16px; text-transform: uppercase; font-weight: 900; letter-spacing: 1px;';
    title.textContent = '🔍 Fingerprint Extractor';
    
    const closeBtn = document.createElement('span');
    closeBtn.style.cssText = 'cursor: pointer; color: #ef4444; font-weight: bold; font-size: 16px; padding: 0 5px;';
    closeBtn.textContent = '✖';
    closeBtn.onclick = () => panel.remove();

    header.appendChild(title);
    header.appendChild(closeBtn);
    panel.appendChild(header);

    // 4. Helper function to create data rows safely
    const addDataRow = (labelText, valueId) => {
        const row = document.createElement('div');
        row.style.cssText = 'margin-bottom: 12px; background: rgba(0,0,0,0.3); padding: 8px; border-radius: 4px; border-left: 3px solid #3b82f6;';
        
        const label = document.createElement('div');
        label.style.cssText = 'font-size: 10px; color: #94a3b8; text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; font-weight: bold;';
        label.textContent = labelText;
        
        const valueBox = document.createElement('div');
        valueBox.id = valueId;
        valueBox.style.cssText = 'font-size: 12px; color: #fbbf24; font-family: "Courier New", Courier, monospace; word-break: break-all;';
        valueBox.textContent = 'Analyzing...';
        
        row.appendChild(label);
        row.appendChild(valueBox);
        panel.appendChild(row);
    };

    // 5. Initialize UI Fields based on requested attributes
    addDataRow('Canvas Hash', 'fp-canvas-hash');
    addDataRow('Browser', 'fp-browser');
    addDataRow('Input IP City', 'fp-input-ip-city');
    addDataRow('Browser Language', 'fp-browser-language');
    addDataRow('Screen Resolution', 'fp-screen-resolution');
    addDataRow('Headers Order String Hash', 'fp-headers-hash');
    addDataRow('Canvas Color Hash', 'fp-color-hash');
    addDataRow('WebGL', 'fp-webgl');
    addDataRow('WebGL Hash', 'fp-webgl-hash');
    addDataRow('HTTP Connection Type', 'fp-connection-type');
    addDataRow('Browser String Hash', 'fp-browser-string-hash');
    addDataRow('True IP Geo', 'fp-true-ip-geo');

    document.body.appendChild(panel);

    // 6. Helper function to update text in the UI
    const updateUI = (id, text, color = '#ffffff') => {
        const el = document.getElementById(id);
        if (el) {
            el.textContent = text;
            el.style.color = color;
        }
    };

    // 7. Simulating a robust hashing algorithm (MurmurHash3 variant for JS)
    const generateHash = (str) => {
        let h1 = 0xdeadbeef, h2 = 0x41c6ce57;
        for (let i = 0, ch; i < str.length; i++) {
            ch = str.charCodeAt(i);
            h1 = Math.imul(h1 ^ ch, 2654435761);
            h2 = Math.imul(h2 ^ ch, 1597334677);
        }
        h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
        h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
        return (4294967296 * (2097151 & h2) + (h1 >>> 0)).toString(16);
    };

    // ==========================================
    // EXTRACTION LOGIC
    // ==========================================

    // A. Canvas Hash
    try {
        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillStyle = '#f60';
        ctx.fillRect(125,1,62,20);
        ctx.fillStyle = '#069';
        ctx.fillText('Fingerprint', 2, 15);
        ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
        ctx.fillText('Fingerprint', 4, 17);
        const dataURL = canvas.toDataURL();
        updateUI('fp-canvas-hash', generateHash(dataURL));
    } catch (e) {
        updateUI('fp-canvas-hash', 'Blocked by Browser', '#ef4444');
    }

    // B. Browser Name & Browser String Hash
    const ua = navigator.userAgent;
    let browserName = "Unknown";
    if (ua.includes("Firefox")) browserName = "Firefox";
    else if (ua.includes("Edg")) browserName = "Microsoft Edge";
    else if (ua.includes("Chrome")) browserName = "Chrome";
    else if (ua.includes("Safari")) browserName = "Safari";
    
    updateUI('fp-browser', browserName);
    updateUI('fp-browser-string-hash', generateHash(ua) + ` (Raw: ${ua.substring(0, 30)}...)`);

    // C. Browser Language
    updateUI('fp-browser-language', navigator.language || navigator.userLanguage);

    // D. Screen Resolution
    updateUI('fp-screen-resolution', `${window.screen.width}x${window.screen.height}`);

    // E. Canvas Color Hash (Approximated using color depth, pixel depth, and gamut)
    const colorData = `${window.screen.colorDepth}|${window.screen.pixelDepth}|${window.matchMedia("(color-gamut: p3)").matches}`;
    updateUI('fp-color-hash', generateHash(colorData) + ` (Based on ${window.screen.colorDepth}-bit depth)`);

    // F. WebGL & WebGL Hash
    try {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');
        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
        const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
        updateUI('fp-webgl', renderer);
        updateUI('fp-webgl-hash', generateHash(renderer));
    } catch(e) {
        updateUI('fp-webgl', 'Unsupported or Blocked', '#ef4444');
        updateUI('fp-webgl-hash', 'N/A', '#ef4444');
    }

    // G. HTTP Connection Type (Using Network Information API)
    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    let connectionType = conn ? (conn.effectiveType || conn.type || "Unknown") : "Unknown";
    updateUI('fp-connection-type', connectionType.toUpperCase());

    // H. Headers Order String Hash (Fetching from echo server)
    try {
        let res = await fetch('https://httpbin.org/headers');
        let data = await res.json();
        let headersOrderString = Object.keys(data.headers).join(',');
        updateUI('fp-headers-hash', generateHash(headersOrderString));
    } catch(e) {
        updateUI('fp-headers-hash', 'Fetch Blocked by CSP', '#ef4444');
    }

    // I. Input IP City (Fetching from public GeoIP API)
    try {
        let res = await fetch('https://get.geojs.io/v1/ip/geo.json');
        let data = await res.json();
        updateUI('fp-input-ip-city', `${data.city}, ${data.country} (IP: ${data.ip})`);
    } catch(e) {
        updateUI('fp-input-ip-city', 'Fetch Blocked by CSP or AdBlocker', '#ef4444');
    }

    // J. True IP Geo (WebRTC Leak Test)
    try {
        const peerConnection = new RTCPeerConnection({ iceServers: [] });
        peerConnection.createDataChannel('');
        peerConnection.createOffer().then(offer => peerConnection.setLocalDescription(offer));
        
        let leakFound = false;
        peerConnection.onicecandidate = async (event) => {
            if (event && event.candidate) {
                const ipRegex = /([0-9]{1,3}(\.[0-9]{1,3}){3}|[a-f0-9]{1,4}(:[a-f0-9]{1,4}){7}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.local)/;
                const match = ipRegex.exec(event.candidate.candidate);
                
                if (match) {
                    leakFound = true;
                    let leakedIP = match[1];
                    peerConnection.close();
                    
                    // If it's a local IP (.local or 192.168), we cannot geo-locate it globally.
                    if (leakedIP.includes('.local') || leakedIP.startsWith('192.168') || leakedIP.startsWith('10.')) {
                        updateUI('fp-true-ip-geo', `mDNS / Local IP (${leakedIP}) - Geo Unavailable`, '#fbbf24');
                    } else {
                        // If it's a public IP, try to get its GeoLocation
                        try {
                            let geoRes = await fetch(`https://get.geojs.io/v1/ip/geo/${leakedIP}.json`);
                            let geoData = await geoRes.json();
                            updateUI('fp-true-ip-geo', `${geoData.city}, ${geoData.country} (Leaked IP: ${leakedIP})`, '#10b981');
                        } catch(e) {
                            updateUI('fp-true-ip-geo', `Leaked IP: ${leakedIP} (Geo Fetch Failed)`, '#10b981');
                        }
                    }
                }
            }
        };
        
        // Timeout if no WebRTC leak is found
        setTimeout(() => {
            if (!leakFound) updateUI('fp-true-ip-geo', 'Secured (No WebRTC Leak Detected)', '#10b981');
        }, 3000);
    } catch (e) {
        updateUI('fp-true-ip-geo', 'WebRTC Blocked by Browser Settings', '#10b981');
    }

})();
