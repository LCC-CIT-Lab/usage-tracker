from datetime import datetime, timedelta
from app.models import LogEntry, IPLocation, db


def delete_old_logs():
    threshold_date = datetime.utcnow() - timedelta(days=14)
    LogEntry.query.filter(LogEntry.timestamp <= threshold_date).delete()
    db.session.commit()


def get_lab_info(ip_address):
    """Retrieve lab location and ID based on the user's IP address."""
    ip_location = IPLocation.query.filter_by(ip_address=ip_address).first()
    if ip_location:
        return ip_location.location_name, ip_location.id
    return "Unknown Location", None
