from datetime import datetime, timezone, timedelta

IST_OFFSET = timedelta(hours=5, minutes=30)
IST_TIMEZONE = timezone(IST_OFFSET, name='IST')

def utc_to_ist(utc_dt):
    """Convert UTC datetime to IST"""
    if utc_dt is None:
        return None
    if utc_dt.tzinfo is None:
        utc_dt = utc_dt.replace(tzinfo=timezone.utc)
    ist_dt = utc_dt.astimezone(IST_TIMEZONE)
    return ist_dt

def format_datetime_ist(dt, format_str='%Y-%m-%d %H:%M:%S IST'):
    """Format datetime in IST timezone"""
    if dt is None:
        return 'N/A'
    ist_dt = utc_to_ist(dt)
    return ist_dt.strftime(format_str)

def format_date_ist(dt, format_str='%Y-%m-%d'):
    """Format date in IST timezone"""
    if dt is None:
        return 'N/A'
    ist_dt = utc_to_ist(dt)
    return ist_dt.strftime(format_str)

def now_ist():
    """Get current time in IST"""
    return datetime.now(IST_TIMEZONE)
