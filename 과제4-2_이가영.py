# 202002345 이가영 (포르투갈어과) _ 과제 4-2 코드

import hashlib

def calc_hash(path):
    f = open(path, 'rb')
    data = f.read()
    hash = hashlib.md5(data).hexdigest()
    return hash

if __name__ == "__main__":
    hash_file = input("파일 이름을 넣으세요.")
    hash_value = calc_hash(hash_file)
    #일치확인
    print('파일의 해시 값(md5)은', hash_value, '입니다.')