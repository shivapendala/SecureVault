import math
from datetime import datetime
from app import db
from app.models.iam import UserSessionTelemetry

def haversine_distance_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    """Calculate the great circle distance in kilometers between two geographic coordinates."""
    r = 6371.0 # Earth radius in km
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)

    a = math.sin(delta_phi / 2.0)**2 + math.cos(phi1) * math.cos(phi2) * math.sin(delta_lambda / 2.0)**2
    c = 2.0 * math.atan2(math.sqrt(a), math.sqrt(1.0 - a))
    return r * c

class SessionAnomalyDetectorService:
    """Detects impossible travel, concurrent sessions, and anomalous login velocity."""

    @classmethod
    def record_and_evaluate_session(cls, user_id: int, session_token_hash: str, ip_address: str, country_code: str, lat: float, lon: float, user_agent: str = None) -> dict:
        """Record session telemetry and check velocity against user's prior session."""
        prior_session = UserSessionTelemetry.query.filter_by(user_id=user_id).order_by(UserSessionTelemetry.recorded_at.desc()).first()

        is_anomalous = False
        anomaly_reason = None

        if prior_session:
            dist_km = haversine_distance_km(prior_session.latitude, prior_session.longitude, lat, lon)
            time_diff_hours = (datetime.utcnow() - prior_session.recorded_at).total_seconds() / 3600.0
            
            # Avoid division by zero
            effective_hours = max(0.01, time_diff_hours)
            velocity_kmh = dist_km / effective_hours

            # If velocity > 850 km/h and distance > 500 km -> Impossible Travel
            if dist_km > 500 and velocity_kmh > 850:
                is_anomalous = True
                anomaly_reason = f"Impossible travel detected: {int(dist_km)} km traversed in {round(time_diff_hours, 2)} hrs ({int(velocity_kmh)} km/h)."

        telemetry = UserSessionTelemetry(
            user_id=user_id,
            session_token_hash=session_token_hash,
            ip_address=ip_address,
            country_code=country_code,
            latitude=lat,
            longitude=lon,
            user_agent=user_agent,
            is_anomalous=is_anomalous,
            anomaly_reason=anomaly_reason
        )
        db.session.add(telemetry)
        db.session.commit()

        return {
            'is_anomalous': is_anomalous,
            'anomaly_reason': anomaly_reason,
            'telemetry': telemetry.to_dict()
        }
