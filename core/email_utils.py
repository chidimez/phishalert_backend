import smtplib
from email.mime.text import MIMEText
from jinja2 import Environment, FileSystemLoader
from core.config import settings

env = Environment(loader=FileSystemLoader("templates/emails"))

def send_email(subject: str, recipient: str, template_name: str, context: dict):
    template = env.get_template(template_name)
    content = template.render(**context)
    msg = MIMEText(content, "html")
    msg["Subject"] = subject
    msg["From"] = settings.FROM_EMAIL
    msg["To"] = recipient

    with smtplib.SMTP(settings.SMTP_SERVER, settings.SMTP_PORT) as server:
        server.starttls()
        server.login(settings.SMTP_USERNAME, settings.SMTP_PASSWORD)
        server.sendmail(settings.FROM_EMAIL, recipient, msg.as_string())