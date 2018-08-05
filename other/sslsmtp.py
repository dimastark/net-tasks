#! /usr/local/bin/python

from smtplib import SMTP_SSL as SMTP
from email.mime.text import MIMEText

SMTPserver = 'smtp.gmail.com'
sender = 'dstarkdev@gmail.com'
destination = ['froyoltc@gmail.com']
text_subtype = 'plain'

content = "Can you give me sto rubley?"
subject = "DimaStark message from python"

msg = MIMEText(content, text_subtype)
msg['Subject'] = subject
msg['From'] = sender

conn = SMTP(SMTPserver)
conn.set_debuglevel(False)
conn.login('dstarkdev@gmail.com', "Froyoltc260797")

try:
    conn.sendmail(sender, destination, msg.as_string())
finally:
    conn.quit()
