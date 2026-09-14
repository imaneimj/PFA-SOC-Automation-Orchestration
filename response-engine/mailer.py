import os
import smtplib
from dotenv import load_dotenv
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication

load_dotenv()

def send_email(subject,body,html=False,attachment_path=None,attachment_filename=None):
    server=None
    try:
        smtp_server=os.getenv("SMTP_SERVER")
        smtp_port=os.getenv("SMTP_PORT")
        smtp_user=os.getenv("SMTP_USER")
        smtp_password=os.getenv("SMTP_PASSWORD")
        from_email=os.getenv("FROM_EMAIL")
        to_email=os.getenv("TO_EMAIL")

        if not smtp_server:
            raise ValueError("SMTP_SERVER is not configured.")
        if not smtp_port:
            raise ValueError("SMTP_PORT is not configured.")
        if not from_email:
            raise ValueError("FROM_EMAIL is not configured.")
        if not to_email:
            raise ValueError("TO_EMAIL is not configured.")

        msg=MIMEMultipart()
        msg["Subject"]=subject
        msg["From"]=from_email
        msg["To"]=to_email

        body_part=MIMEText(
            body,
            "html" if html else "plain",
            "utf-8"
        )
        msg.attach(body_part)

        if attachment_path:
            if not os.path.exists(attachment_path):
                raise FileNotFoundError(
                    f"Attachment not found: {attachment_path}"
                )

            filename=attachment_filename or os.path.basename(attachment_path)

            print("[MAILER] Adding attachment:",attachment_path)

            with open(attachment_path,"rb") as attachment_file:
                attachment=MIMEApplication(
                    attachment_file.read(),
                    _subtype="pdf"
                )

            attachment.add_header(
                "Content-Disposition",
                "attachment",
                filename=filename
            )

            msg.attach(attachment)
            print("[MAILER] Attachment added:",filename)

        server=smtplib.SMTP(smtp_server,int(smtp_port))
        server.ehlo()
        server.starttls()
        server.ehlo()

        if smtp_user and smtp_password:
            server.login(smtp_user,smtp_password)

        server.send_message(msg)

        print("[+] Email sent successfully")

        if attachment_path:
            print("[+] PDF attachment sent successfully")

        return {
            "success":True,
            "attachment":attachment_filename if attachment_path else None
        }

    except Exception as e:
        print(f"[ERROR] Email sending failed: {e}")
        raise

    finally:
        if server is not None:
            try:
                server.quit()
            except Exception:
                pass