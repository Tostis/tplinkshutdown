import base64
import hashlib
import json
import math
import time
import requests

from Crypto.Cipher import AES
from Crypto.Random import random

from tplinkshutdown.return_codes import exit_login_error, exit_reboot_error, exit_network_error_login, \
    exit_network_error_obtain_certificate, exit_network_error_reboot


# manual RSA nopadding equals to Textbook. right pad with zeros up to 64 bytes. returns hex string
def myrsanecryptor(nn: int, ee: int, text: str) -> str:
    passwordbytes: bytes = text.encode("utf8")
    # right pad with zeros up to 64 bytes
    passlen: int = len(passwordbytes)
    while passlen < 64:
        passwordbytes += b'\x00'
        passlen += 1
    # RSA no padding
    # https://github.com/pyca/cryptography/issues/2735
    # cipher_text = publickey.encrypt(passwordbytes, 0)[0] # not implemented into the newer versions of crypto library
    # so I will implement it here
    keylength = math.ceil(nn.bit_length() / 8)
    # theoretically byteorder should be sys.byteorder but javascript is always big endian
    input_nr = int.from_bytes(passwordbytes, byteorder='big')
    # encrypt.js -> RSADoPublic
    crypted_nr = pow(input_nr, ee, nn)
    # theoretically byteorder should be sys.byteorder but javascript is always big endian
    crypted_data = crypted_nr.to_bytes(keylength, byteorder='big')
    encrypted = crypted_data.hex()
    print('rsa_encrypted_manual: ' + encrypted)
    return encrypted


# rsa crypt using public key with 64 chars blocks
def rsasignature(n: int, e: int, plaintext: str):
    signature_result: str = ''
    pos: int = 0
    maxlength: int = 64
    while pos < len(plaintext):
        signature_result += myrsanecryptor(n, e, plaintext[pos:pos + maxlength])
        pos += maxlength
    return signature_result


# crypt using aes CBC algorithm. returns base64 encoded string
def aesencrypt(aes_key: bytes, aes_iv: bytes, plain_text: str) -> str:
    aes_encryptor = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    data: bytes = plain_text.encode("utf8")  # <- 16 bytes
    # make data a multiple of 16 appending bytes with value = length (any value is fine)
    length = 16 - (len(data) % 16)
    data += bytes([length]) * length
    aes_encrypted: bytes = aes_encryptor.encrypt(data)
    aes_encrypted_base64: str = base64.b64encode(aes_encrypted).decode('ascii')
    return aes_encrypted_base64


# decrypt a base64 encoded string using aes CBC algorithm
def aesdecrypt(aes_key: bytes, aes_iv: bytes, crypt_text: str) -> str:
    dec_base64: bytes = base64.b64decode(crypt_text)
    aes_decryptor = AES.new(aes_key, AES.MODE_CBC, aes_iv)
    plain_text = str(aes_decryptor.decrypt(dec_base64))
    return plain_text


def cleanresponse(raw_response: str) -> str:
    return raw_response.replace("b\'", "").replace("\'", "").replace("\\n", "").replace("\\t", "") \
        .replace("\\x02", "").replace("\\x01", "")


def restart(username: str, password: str, base_url: str) -> int:

    asterisk: str = '*' * len(password)
    print("Rebooting " + base_url + ' with password ' + asterisk)

    # phase 1 begin: obtain certificate containing key and exponent
    print('phase 1 begin: obtain certificate containing key and exponent')
    auth_url = base_url + '/login?form=auth'
    auth_post_data = {'operation': 'read'}

    try:
        auth_response: requests.Response = requests.post(auth_url, data=auth_post_data)
    except requests.exceptions.RequestException as e:
        print(e)
        return exit_network_error_obtain_certificate

    parsed_json = (json.loads(auth_response.text))

    rsa_exponent: str = parsed_json["data"]["key"][1]
    rsa_key = parsed_json["data"]["key"][0]
    seq = parsed_json["data"]["seq"]
    # phase 1 end

    sleep_seconds: int = 1
    print('sleeping ' + str(sleep_seconds) + ' seconds')
    time.sleep(sleep_seconds)

    # phase 2 begin: login
    print('phase 2 begin: login')

    # encrypt.js-> RSASetPublic(N,E)
    e: int = int(rsa_exponent, 16)
    n: int = int(rsa_key, 16)
    seqint: int = int(seq, 10)

    rsa_encrypted = myrsanecryptor(n, e, password)

    md5hash = hashlib.md5((username + password).encode("utf8")).hexdigest()
    # TODO random number
    aes_key = b'1527039873676296'
    aes_iv = b'1527039905151470'

    datastr: str = 'operation=login&password=' + rsa_encrypted

    encd_base64: str = aesencrypt(aes_key, aes_iv, datastr)

    aes_key_string: str = 'k=' + str(aes_key, "utf8") + '&i=' + str(aes_iv, "utf8")
    current_seqint = seqint + len(encd_base64)
    signstr: str = aes_key_string + '&h=' + md5hash + '&s=' + str(current_seqint)

    signature: str = rsasignature(n, e, signstr)

    login_url = base_url + '/login?form=login'
    login_post_data = {'sign': signature, 'data': encd_base64}
    login_headers = {'Referer': base_url}

    print("login post data: " + json.dumps(login_post_data, indent=4))

    try:
        login_response: requests.Response = requests.post(login_url, data=login_post_data, headers=login_headers)
    except requests.exceptions.RequestException as e:
        print(e)
        return exit_network_error_login

    print('login_response body: ' + login_response.request.body)
    print('login_response response: ' + login_response.text)

    parsed_json = (json.loads(login_response.text))

    login_result: str = parsed_json["data"]
    print('login_result: ' + login_result)

    login_result_dec: str = aesdecrypt(aes_key, aes_iv, login_result)
    cleaned = cleanresponse(login_result_dec)
    parsed_json = (json.loads(cleaned))
    print('login_result_decrypted: ' + json.dumps(parsed_json))

    if not parsed_json["success"]:
        return exit_login_error
    # phase 2 end

    print('sleeping ' + str(sleep_seconds) + ' seconds')
    time.sleep(sleep_seconds)
    # phase 3 begin: reboot
    print('phase 3 begin: reboot')
    reboot_url: str = base_url + '/admin/reboot.json'

    signature = rsasignature(n, e, signstr)
    encd_base64 = aesencrypt(aes_key, aes_iv, "operation=write")
    current_seqint = seqint + len(encd_base64)
    signstr = 'h=' + md5hash + '&s=' + str(current_seqint)

    reboot_post_data = {'sign': signature, 'data': encd_base64}

    print("reboot post data: " + json.dumps(reboot_post_data, indent=4))

    try:
        reboot_response: requests.Response = requests.post(reboot_url, data=reboot_post_data, headers=login_headers)
    except requests.exceptions.RequestException as e:
        print(e)
        return exit_network_error_reboot

    print('reboot_response body: ' + reboot_response.request.body)
    print('reboot_response response: ' + reboot_response.text)

    parsed_json = (json.loads(reboot_response.text))

    reboot_result: str = parsed_json["data"]
    print('reboot_result: ' + reboot_result)

    reboot_result_dec: str = aesdecrypt(aes_key, aes_iv, reboot_result)
    cleaned = cleanresponse(reboot_result_dec)
    parsed_json = (json.loads(cleaned))
    print('reboot_result_decrypted: ' + json.dumps(parsed_json))
    if not parsed_json["success"]:
        return exit_reboot_error
    print('Reboot OK')
    # phase 3 end
