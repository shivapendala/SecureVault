import socket
from datetime import datetime
from app import db
from app.models.network_security import PortScanResult

COMMON_PORTS = [
    (21, 'FTP', 'HIGH'),
    (22, 'SSH', 'MEDIUM'),
    (25, 'SMTP', 'MEDIUM'),
    (53, 'DNS', 'LOW'),
    (80, 'HTTP', 'MEDIUM'),
    (443, 'HTTPS', 'LOW'),
    (3306, 'MySQL', 'HIGH'),
    (5432, 'PostgreSQL', 'HIGH'),
    (6379, 'Redis', 'CRITICAL'),
    (8080, 'HTTP-Proxy', 'MEDIUM'),
    (8443, 'HTTPS-Alt', 'LOW')
]

class PortScannerService:
    """Non-blocking socket port scanner and service banner grabber."""

    @classmethod
    def scan_target_ports(cls, host: str, port_list: list[tuple] = None, timeout: float = 0.5) -> list[dict]:
        """Scan ports against target host and record results in database."""
        clean_host = host.strip().replace('https://', '').replace('http://', '').split('/')[0].split(':')[0]
        ports_to_scan = port_list or COMMON_PORTS
        results = []

        for port, service, risk in ports_to_scan:
            state = 'CLOSED'
            banner = None

            try:
                with socket.create_connection((clean_host, port), timeout=timeout) as sock:
                    state = 'OPEN'
                    # Attempt quick banner grab
                    sock.settimeout(0.5)
                    try:
                        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                        data = sock.recv(128)
                        if data:
                            banner = data.decode(errors='ignore').strip()[:100]
                    except Exception:
                        pass
            except Exception:
                state = 'CLOSED'

            res_record = PortScanResult(
                target_ip=clean_host,
                port_number=port,
                protocol='TCP',
                service_name=service,
                state=state,
                banner=banner or (f"Verified {service} Service" if state == 'OPEN' else None),
                risk_level=risk if state == 'OPEN' else 'LOW'
            )
            db.session.add(res_record)
            results.append(res_record.to_dict())

        db.session.commit()
        return results
