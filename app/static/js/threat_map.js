/**
 * SecureVault Global Threat Map Visualizer
 * Real-time Canvas/SVG rendering engine for global cybersecurity telemetry, attack arcs, and IoC coordinates.
 */
class SecureVaultThreatMap {
    constructor(canvasId, options = {}) {
        this.canvas = document.getElementById(canvasId);
        if (!this.canvas) return;
        this.ctx = this.canvas.getContext('2d');
        this.width = this.canvas.width = options.width || this.canvas.offsetWidth || 1200;
        this.height = this.canvas.height = options.height || 600;
        this.arcs = [];
        this.nodes = [];
        this.maxArcs = options.maxArcs || 25;
        this.animationFrame = null;
        this.init();
    }

    init() {
        this.setupDefaultNodes();
        this.bindEvents();
        this.startRenderLoop();
    }

    setupDefaultNodes() {
        this.nodes = [
            { name: 'SOC Headquarters (US-East)', lat: 38.8951, lon: -77.0364, type: 'hq', color: '#00f2fe' },
            { name: 'EU Cloud Enclave (Frankfurt)', lat: 50.1109, lon: 8.6821, type: 'datacenter', color: '#4facfe' },
            { name: 'APAC Node (Tokyo)', lat: 35.6762, lon: 139.6503, type: 'datacenter', color: '#4facfe' },
            { name: 'Tor Exit Node (Malicious)', lat: 52.5200, lon: 13.4050, type: 'threat', color: '#ff4b72' },
            { name: 'C2 Cobalt Strike Listener', lat: 55.7558, lon: 37.6173, type: 'threat', color: '#ff4b72' },
            { name: 'Typosquatting Harvester', lat: 31.2304, lon: 121.4737, type: 'threat', color: '#ffb300' }
        ];
    }

    projectCoords(lat, lon) {
        const x = (lon + 180) * (this.width / 360);
        const latRad = lat * Math.PI / 180;
        const mercN = Math.log(Math.tan((Math.PI / 4) + (latRad / 2)));
        const y = (this.height / 2) - (this.width * mercN / (2 * Math.PI));
        return { x: Math.max(20, Math.min(this.width - 20, x)), y: Math.max(20, Math.min(this.height - 20, y)) };
    }

    addAttackArc(source, target, threatType = 'SQL_INJECTION') {
        const p1 = this.projectCoords(source.lat, source.lon);
        const p2 = this.projectCoords(target.lat, target.lon);
        const arc = {
            p1, p2,
            progress: 0,
            speed: 0.015 + Math.random() * 0.02,
            color: threatType.includes('CRITICAL') ? '#ff4b72' : '#00f2fe',
            threatType: threatType
        };
        this.arcs.push(arc);
        if (this.arcs.length > this.maxArcs) this.arcs.shift();
    }

    drawBackground() {
        this.ctx.fillStyle = '#060a14';
        this.ctx.fillRect(0, 0, this.width, this.height);
        this.ctx.strokeStyle = 'rgba(0, 242, 254, 0.05)';
        this.ctx.lineWidth = 1;
        const gridSize = 40;
        for (let x = 0; x < this.width; x += gridSize) {
            this.ctx.beginPath();
            this.ctx.moveTo(x, 0);
            this.ctx.lineTo(x, this.height);
            this.ctx.stroke();
        }
        for (let y = 0; y < this.height; y += gridSize) {
            this.ctx.beginPath();
            this.ctx.moveTo(0, y);
            this.ctx.lineTo(this.width, y);
            this.ctx.stroke();
        }
    }

    drawNodes() {
        this.nodes.forEach(node => {
            const { x, y } = this.projectCoords(node.lat, node.lon);
            this.ctx.beginPath();
            this.ctx.arc(x, y, 6, 0, Math.PI * 2);
            this.ctx.fillStyle = node.color;
            this.ctx.fill();
            this.ctx.beginPath();
            this.ctx.arc(x, y, 12, 0, Math.PI * 2);
            this.ctx.strokeStyle = node.color;
            this.ctx.lineWidth = 1.5;
            this.ctx.stroke();
            this.ctx.font = '10px "JetBrains Mono", monospace';
            this.ctx.fillStyle = '#94a3b8';
            this.ctx.fillText(node.name, x + 12, y + 4);
        });
    }

    drawArcs() {
        for (let i = this.arcs.length - 1; i >= 0; i--) {
            const arc = this.arcs[i];
            arc.progress += arc.speed;
            const midX = (arc.p1.x + arc.p2.x) / 2;
            const midY = (arc.p1.y + arc.p2.y) / 2 - 50;
            this.ctx.beginPath();
            this.ctx.moveTo(arc.p1.x, arc.p1.y);
            this.ctx.quadraticCurveTo(midX, midY, arc.p2.x, arc.p2.y);
            this.ctx.strokeStyle = 'rgba(255, 75, 114, 0.2)';
            this.ctx.lineWidth = 2;
            this.ctx.stroke();
            const t = arc.progress;
            const currX = (1 - t) * (1 - t) * arc.p1.x + 2 * (1 - t) * t * midX + t * t * arc.p2.x;
            const currY = (1 - t) * (1 - t) * arc.p1.y + 2 * (1 - t) * t * midY + t * t * arc.p2.y;
            this.ctx.beginPath();
            this.ctx.arc(currX, currY, 4, 0, Math.PI * 2);
            this.ctx.fillStyle = arc.color;
            this.ctx.fill();
            if (arc.progress >= 1) this.arcs.splice(i, 1);
        }
    }

    startRenderLoop() {
        const loop = () => {
            this.drawBackground();
            this.drawNodes();
            this.drawArcs();
            if (Math.random() < 0.05) {
                const src = this.nodes[3 + Math.floor(Math.random() * 3)];
                const tgt = this.nodes[Math.floor(Math.random() * 3)];
                this.addAttackArc(src, tgt, 'DDOS_SYN_FLOOD');
            }
            this.animationFrame = requestAnimationFrame(loop);
        };
        loop();
    }

    bindEvents() {
        window.addEventListener('resize', () => {
            if (this.canvas) {
                this.width = this.canvas.width = this.canvas.offsetWidth || 1200;
                this.height = this.canvas.height = this.canvas.offsetHeight || 600;
            }
        });
    }

    destroy() {
        if (this.animationFrame) cancelAnimationFrame(this.animationFrame);
    }
}

window.SecureVaultThreatMap = SecureVaultThreatMap;
