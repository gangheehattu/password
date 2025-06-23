
import os
import base64
import hashlib
import getpass
import secrets

DATA_FILE = 'passwords.dat'
SALT_FILE = DATA_FILE + '.salt'

class PasswordManager:
    def __init__(self, data_path, salt_path):
        self.data_path = data_path
        self.salt_path = salt_path
        self.salt = self._load_or_create_salt()
        self.key = self._derive_key()

    def _load_or_create_salt(self):
        if not os.path.exists(self.salt_path):
            salt = secrets.token_bytes(16)
            with open(self.salt_path, 'wb') as f:
                f.write(salt)
        else:
            with open(self.salt_path, 'rb') as f:
                salt = f.read()
        return salt

    def _derive_key(self):
        master_pw = getpass.getpass('마스터 암호 입력: ')
        # PBKDF2-HMAC-SHA256 으로 256비트 키 생성
        return hashlib.pbkdf2_hmac('sha256', master_pw.encode(), self.salt, 100_000)

    def _xor_cipher(self, data: bytes) -> bytes:
        return bytes(b ^ self.key[i % len(self.key)] for i, b in enumerate(data))

    def _encrypt(self, plaintext: str) -> str:
        ct = self._xor_cipher(plaintext.encode('utf-8'))
        return base64.urlsafe_b64encode(ct).decode('utf-8')

    def _decrypt(self, cipher_b64: str) -> str:
        ct = base64.urlsafe_b64decode(cipher_b64.encode('utf-8'))
        pt = self._xor_cipher(ct)
        return pt.decode('utf-8')

    def add(self, site, user, pw):
        record = f'{site},{user},{pw}'
        cipher = self._encrypt(record)
        with open(self.data_path, 'a', encoding='utf-8') as f:
            f.write(cipher + '\n')
        print('암호 추가 완료')

    def view(self):
        if not os.path.exists(self.data_path):
            print('등록된 암호가 없습니다.')
            return
        with open(self.data_path, 'r', encoding='utf-8') as f:
            for idx, line in enumerate(f, 1):
                line = line.strip()
                if not line:
                    continue
                try:
                    site, user, pw = self._decrypt(line).split(',', 2)
                    print(f'[{idx}] 사이트: {site}, 계정: {user}, 암호: {pw}')
                except Exception:
                    print(f'[{idx}] 복호화 오류')

    def delete(self, idx: int):
        if not os.path.exists(self.data_path):
            print('등록된 암호가 없습니다.')
            return
        with open(self.data_path, 'r', encoding='utf-8') as f:
            lines = [l.strip() for l in f if l.strip()]
        if idx < 1 or idx > len(lines):
            print('잘못된 번호')
            return
        lines.pop(idx-1)
        with open(self.data_path, 'w', encoding='utf-8') as f:
            for l in lines:
                f.write(l + '\n')
        print(f'[{idx}] 항목 삭제 완료')

def main():
    pm = PasswordManager(DATA_FILE, SALT_FILE)

    while True:
        print('\n암호 관리 프로그램')
        print('1. 암호 추가')
        print('2. 암호 조회')
        print('3. 암호 삭제')
        print('4. 종료')
        choice = input('선택> ').strip()

        if choice == '1':
            site = input('사이트 이름: ').strip()
            user = input('계정 이름: ').strip()
            pw   = input('암호: ').strip()
            pm.add(site, user, pw)
        elif choice == '2':
            pm.view()
        elif choice == '3':
            pm.view()
            num = input('삭제할 번호> ').strip()
            if num.isdigit():
                pm.delete(int(num))
            else:
                print('번호를 숫자로 입력하세요.')
        elif choice == '4':
            print('프로그램 종료')
            break
        else:
            print('올바른 선택이 아닙니다.')

if __name__ == '__main__':
    main()
