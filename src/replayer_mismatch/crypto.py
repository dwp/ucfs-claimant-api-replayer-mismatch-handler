import base64
from Crypto.Cipher import AES


def decrypted_data_key(kms_client, encrypted_key):
    cipher = base64.urlsafe_b64decode(encrypted_key)
    decrypted_key_response = kms_client.decrypt(CiphertextBlob=cipher)
    return decrypted_key_response['Plaintext']


def decrypted_take_home_pay(decrypted_key, encrypted_take_home_pay):
    iv = encrypted_take_home_pay[:16]
    encrypted = encrypted_take_home_pay[16:]
    aes = AES.new(decrypted_key, AES.MODE_GCM, nonce=base64.urlsafe_b64decode(iv))
    raw = base64.urlsafe_b64decode(encrypted)
    return aes.decrypt_and_verify(raw[:-16], raw[-16:]).decode("ASCII")
