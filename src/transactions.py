import signatures

class Transaction:
	incoming_data = None
	outgoing_data = None
	moderator = None

	def __init__(self):
		self.incoming_data = []
		self.outgoing_data = []
		self.moderator = []
		self.signatures = []

	# from where the amount is being sent
	def create_input_data(self, sender_address, amount):
		self.incoming_data.append((sender_address, amount))
		return self.incoming_data

	# to whom the amount is being sent
	def create_output_data(self, receiver_address, amount):
		self.outgoing_data.append((receiver_address, amount))
		return self.outgoing_data

	def set_moderator(self, moderator_address):
		self.moderator.append(moderator_address)
		return self.moderator

	def __create_data(self):
		data = []
		data.append(self.incoming_data)
		data.append(self.outgoing_data)
		data.append(self.moderator)
		return data

	def sign(self, private_key):
		transaction_block = self.__create_data()
		new_signature = signatures.sign_message(transaction_block, private_key)
		self.signatures.append(new_signature)

	def is_valid(self):
		total_amount_in = 0
		total_amount_out = 0
		transaction_block = self.__create_data()
		for address, amount in self.incoming_data:
			found = False
			for signature in self.signatures:
				if signatures.verify_signature(transaction_block, signature, address):
					found = True
			if not found:
				return False

			if amount <= 0:
				return False
			total_amount_in = total_amount_in + amount

		for address in self.moderator:
			found = False
			for signature in self.signatures:
				if signatures.verify_signature(transaction_block, signature, address):
					found = True
			if not found:
				return False

		for address, amount in self.outgoing_data:
			if amount <= 0:
				return False
			total_amount_out = total_amount_out + amount

		if total_amount_out > total_amount_in:
			return False

		return True



if __name__ == "__main__":
	prv, pub = signatures.generate_keys()
	prv1, pub1 = signatures.generate_keys()
	prv2, pub2 = signatures.generate_keys()
	prv3, pub3 = signatures.generate_keys()
	t1 = Transaction()
	t1.create_input_data(pub, 1)
	t1.create_output_data(pub1, 1)
	t1.sign(prv)

	if t1.is_valid():
		print("Success transaction was successful")
	else:
		print("Error transaction was not successful")


	# transaction signed by the wrong private key
	t2 = Transaction()
	t2.create_input_data(pub2, 1)
	t2.create_output_data(pub3, 1)
	t2.sign(prv)

	if t2.is_valid():
		print("Success transaction was successful")
	else:
		print("Error transaction was not successful")


	# transaction with negative values
	t3 = Transaction()
	t3.create_input_data(pub2, -1)
	t3.create_output_data(pub3, -1)
	t3.sign(prv2)

	if t3.is_valid():
		print("Success transaction was successful")
	else:
		print("Error transaction was not successful")


	# transaction with excess amount output
	t4 = Transaction()
	t4.create_input_data(pub2, 1)
	t4.create_output_data(pub3, 5)
	t4.sign(prv2)

	if t4.is_valid():
		print("Success transaction was successful")
	else:
		print("Error transaction was not successful")
