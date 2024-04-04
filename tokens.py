from itsdangerous import URLSafeTimedSerializer,SignatureExpired
import random
from key import *
serializer=URLSafeTimedSerializer(secret_key)
def generate_otp(lenght=6):
    return ''.join([str(random.randint(0,9)) for _ in range(lenght)])


#Functiom to create token
def create_token(data,salt):
    token=serializer.dumps(data,salt=salt)
    return token

#function to verify the created token
def verify_token(token,salt,expiration=600):
    try:
        token_data=serializer.loads(token,salt=salt,max_age=expiration)
        return token_data
    except SignatureExpired:
        print('token Expired')
        return None
# if __name__=='__main__':
#     # data={'Name':'cse','Mobile':'3477473892'}
#     # #token=create_token(data,salt=salt)
#     # token='eyJOYW1lIjoiY3NlIiwiTW9iaWxlIjoiMzQ3NzQ3Mzg5MiJ9.ZfKXIQ.Mnpf2QnuVGZFHZbw0fHmCI9srqU'
#     # print(token)
#     # token_data=verify_token(token,salt=salt)
#     # print(token_data)
