import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from tokens import *
smail='chsrinu0066@gmail.com'
passcode='ntbq rass gkhx tevh'
def sendmail(rmail,subject,body,smail=smail,passcode=passcode):
    try:
        msg=MIMEMultipart()
        msg['From']='chsrinu0066@gmail.com'
        msg['To']=rmail
        msg['Subject']=subject
        msg.attach(MIMEText(body,'html'))
        server=smtplib.SMTP_SSL('smtp.gmail.com',465)
        server.login(smail,passcode)
        server.send_message(msg)
        server.quit()
    except Exception as e:
        print('Error in sendionmg mail',e)
        return False