/**
 * SecureVault Real-time Cyber Telemetry Stream Parser & Event Buffer
 */
class SecureVaultTelemetryStream {
    constructor(options = {}) {
        this.buffer = [];
        this.maxBufferSize = options.maxBufferSize || 1000;
        this.eventListeners = new Map();
        this.isStreaming = false;
        this.pollInterval = null;
    }

    startStream(endpoint = '/api/security-logs?limit=50', intervalMs = 3000) {
        if (this.isStreaming) return;
        this.isStreaming = true;
        this.pollInterval = setInterval(async () => {
            try {
                const response = await fetch(endpoint);
                if (!response.ok) return;
                const data = await response.json();
                if (data && data.logs) {
                    data.logs.forEach(log => this.ingestEvent(log));
                }
            } catch (err) {
                console.warn('[TelemetryStream] Ingestion poll error:', err);
            }
        }, intervalMs);
    }

    stopStream() {
        if (this.pollInterval) clearInterval(this.pollInterval);
        this.isStreaming = false;
    }

    ingestEvent(event) {
        if (!event || !event.id) return;
        const exists = this.buffer.some(e => e.id === event.id);
        if (!exists) {
            this.buffer.unshift(event);
            if (this.buffer.length > this.maxBufferSize) this.buffer.pop();
            this.emit('event', event);
            if (event.severity === 'CRITICAL' || event.severity === 'HIGH') {
                this.emit('alert', event);
            }
        }
    }

    on(eventName, callback) {
        if (!this.eventListeners.has(eventName)) {
            this.eventListeners.set(eventName, []);
        }
        this.eventListeners.get(eventName).push(callback);
    }

    emit(eventName, data) {
        const listeners = this.eventListeners.get(eventName) || [];
        listeners.forEach(cb => {
            try { cb(data); } catch (e) { console.error(e); }
        });
    }

    getRecentEvents(limit = 10) {
        return this.buffer.slice(0, limit);
    }
}

window.SecureVaultTelemetryStream = SecureVaultTelemetryStream;
