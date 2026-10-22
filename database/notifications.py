# database/notifications.py
from database.telegram import send_message

def notify_new_live_subdomain(subdomain: str, program_name: str):
    """Notify when a new live subdomain is discovered"""
    message = f"🟢 <b>New Live Subdomain</b>\n\n<code>{subdomain}</code>\n\nProgram: {program_name}"
    send_message(message)

def notify_updated_live_subdomain_ip(subdomain: str, program_name: str):
    """Notify when a  live subdomain is updated"""
    message = f"🟢 <b>updated Live Subdomain ip</b>\n\n<code>{subdomain}</code>\n\nProgram: {program_name}"
    send_message(message)

def notify_updated_live_subdomain_cdn(subdomain: str, program_name: str, new_cdn: str):
    """Notify when a  live subdomain is updated"""
    message = f"🟢 <b>updated Live Subdomain cdn</b>\n<code>CDN: {new_cdn}</code>\n\n<code>{subdomain}</code>\n\nProgram: {program_name}"
    send_message(message)

def notify_new_http(subdomain: str, program_name: str):
    """Notify when new HTTP record is added"""
    message = f"🌐 <b>New HTTP Record</b>\n\n<code>{subdomain}</code>\n\nProgram: {program_name}"
    send_message(message)
