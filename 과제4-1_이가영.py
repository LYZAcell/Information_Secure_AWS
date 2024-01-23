# 202002345 이가영 (포르투갈어과) _ 4-1 과제 코드

import base64
import hashlib
from Crypto.Cipher import AES

BS = 16
pad = (lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS).encode())
unpad = (lambda s: s[:-ord(s[len(s)-1:])])

class AESCipher(object):
    
    # 키를 설정해주는 함수. 정보보안을 뜻하는 InfoSecure로 키를 설정하였습니다. 
    def __init__(self):
        user_key = "InfoSecure"
        self.key = hashlib.sha256(user_key.encode()).digest()
    
    # 암호화 함수. 입력받은 메세지를 암호화합니다
    def encrypt(self, message):
        message = message.encode()
        raw = pad(message)
        cipher = AES.new(self.key, AES.MODE_CBC, self.__iv().encode('utf8'))
        enc = cipher.encrypt(raw)
        return base64.b64encode(enc).decode('utf-8')
    
    # 복호화 함수. 입력받은 암호를 복호화합니다
    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        cipher = AES.new(self.key, AES.MODE_CBC, self.__iv().encode('utf8'))
        dec = cipher.decrypt(enc)
        return unpad(dec).decode('utf-8')
    
    def __iv(self):
        return chr(0) * 16
    

def menu():
    print("1. 암호화")
    print("2. 복호화")

def main():
    cipher = AESCipher()

    while True:
        menu()
        choice = input("메뉴를 선택하세요 (1 또는 2): ")

        if choice == '1':
            text = input("문장을 입력하세요: ")
            enc_message = cipher.encrypt(text)
            print(f"암호화: {enc_message}")
            
            
        elif choice == '2':
            enc_message = input("암호화된 문장을 입력하세요: ")
            dec_message = cipher.decrypt(enc_message)
            print(f"복호화: {dec_message}")
        else:
            print("올바른 메뉴를 선택하세요.")

        again = input("계속하시겠습니까? (y/n): ")
        if again.lower() != 'y':
            break

if __name__ == "__main__":
    main()