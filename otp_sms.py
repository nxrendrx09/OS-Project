from twilio.rest import Client
import random

account_sid = 'AC16001f3fc40ea7f1f159547ca6a07232'
auth_token = '0da0d06f2f9e1c59d0a6c1f495d5acb0'
twilio_number = '+1 878 251 2924'

client = Client(account_sid, auth_token)

import time
otp_storage = {}  # phone_number: (otp, timestamp)


def generate_otp():
    return str(random.randint(100000, 999999))

def send_otp_sms(phone_number):
    otp = generate_otp()
    client.messages.create(
        body=f"Your OTP is {otp}",
        from_=twilio_number,
        to=phone_number
    )
 otp_storage[phone_number] = (otp, time.time())


def verify_otp(phone_number, entered_otp):
    data = otp_storage.get(phone_number)
    if not data:
        return False

    otp, timestamp = data
    
    # OTP expires in 180 seconds (3 minutes)
    if time.time() - timestamp > 180:
        return False

    return otp == entered_otp
