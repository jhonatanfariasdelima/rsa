import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def utf8(s: bytes):
    return str(s, 'utf-8')

def Generate_keys():
	private_key = rsa.generate_private_key(
	    public_exponent=65537,
	    key_size=4096,
	    backend=default_backend()
	)

	private_pem = private_key.private_bytes(
	    encoding=serialization.Encoding.PEM,
	    format=serialization.PrivateFormat.PKCS8,
	    encryption_algorithm=serialization.NoEncryption()
	)

	with open('private_key.pem', 'wb') as f:
	    f.write(private_pem)
	    f.close()
	    
	with open("private_key.pem", "rb") as key_file:
    		private_key = serialization.load_pem_private_key(
        	key_file.read(),
        	password=None,
        	backend=default_backend()
    	)

	public_key = private_key.public_key()

	public_pem = public_key.public_bytes(
	    encoding=serialization.Encoding.PEM,
	    format=serialization.PublicFormat.SubjectPublicKeyInfo
	)
	with open('public_key.pem', 'wb') as f:
	    f.write(public_pem)
	    f.close()

	with open("public_key.pem", "rb") as key_file:
	    public_key = serialization.load_pem_public_key(
		key_file.read(),
		backend=default_backend()
	    )
	return [private_key, public_key]

def encrypt():
	plaintext = b'hackear a nasa!'
	print(f'mensagem: \033[1;33m{utf8(plaintext)}\033[0m')
	encrypted = base64.b64encode(keys[1].encrypt(
	    plaintext,
	    padding.OAEP(
		mgf=padding.MGF1(algorithm=hashes.SHA256()),
		algorithm=hashes.SHA256(),
		label=None
	    )
	))
	return encrypted

def decrypt(encrypted):
	decrypted = keys[0].decrypt(
	    base64.b64decode(encrypted),
	    padding.OAEP(
		mgf=padding.MGF1(algorithm=hashes.SHA256()),
		algorithm=hashes.SHA256(),
		label=None
	    )
	)
	print(f'mensagem decifrada: \033[1;31m{utf8(decrypted)}\033[0m')


keys = Generate_keys()

encrypt = encrypt()

decrypt = decrypt(encrypt)

    