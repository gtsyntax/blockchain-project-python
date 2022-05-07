from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

def generate_keys():
	private_key = rsa.generate_private_key(
		public_exponent=65537,
		key_size=2048,
		backend=default_backend()
	)

	public_key = private_key.public_key()
	return private_key, public_key

def sign_message(message, private_key):
	signature = private_key.sign(
		message,
		padding.PSS(
			mgf=padding.MGF1(hashes.SHA256()),
			salt_length=padding.PSS.MAX_LENGTH
		),
		hashes.SHA256()
	)

	return signature

def verify_signature(message, signature, public_key):
	try:
		public_key.verify(
			signature,
			message,
			padding.PSS(
				mgf=padding.MGF1(hashes.SHA256()),
				salt_length=padding.PSS.MAX_LENGTH
			),
			hashes.SHA256()
		)
		return True

	except InvalidSignature:
		return False

	except:
		print("Something went wrong!")
		return False

if __name__ == "__main__":

	# corresponding private and public key verification -> testcase should pass
	prv,pub = generate_keys()
	message = b"This is a secreat message"
	signature = sign_message(message, prv)
	is_correct = verify_signature(message, signature, pub)

	if is_correct:
		print("Success! Good signature")
	else:
		print("Error! signature is bad")

	# non-corresponding private and public key verification -> testcase should fail
	prv2, pub2 = generate_keys()
	signature2 = sign_message(message, prv2)
	is_correct2 = verify_signature(message, signature2, pub)

	if is_correct2:
		print("Success! Good signature")
	else:
		print("Error! Signature is bad")

	# altered message testing
	altered_message = message + b"attacker"
	is_correct3 = verify_signature(altered_message, signature, pub)
	if is_correct3:
		print("Error! Altered message passed!")
	else:
		print("Success! Altered message detected")

