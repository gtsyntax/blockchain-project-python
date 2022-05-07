from datetime import datetime
from cryptography.hazmat.primitives import hashes

class Block:
	data = None
	previous_hash = None
	previous_block = None
	timestamp = None

	def __init__(self, data, previous_block):
		self.data = data
		self.previous_block = previous_block
		if self.previous_block != None:
			self.previous_hash = previous_block.compute_hash()
		self.timestamp = datetime.now().isoformat()


	def compute_hash(self):
		digest = hashes.Hash(hashes.SHA256())
		digest.update(bytes(str(self.data), "utf-8"))
		digest.update(bytes(str(self.previous_hash), "utf-8"))
		return digest.finalize()


if __name__ == "__main__":
	block1 = Block("test", None)
	block2 = Block("test1", block1)

	# testing to ensure the hashes are the same
	if block2.previous_block.compute_hash() == block2.previous_hash:
		print("Success!")
	else:
		print("Error!")


	# testing to ensure that if the data changes the new hash won't be equal to the original hash
	block1.data = 12345
	if block2.previous_block.compute_hash() == block2.previous_hash:
		print("Error! data change not detected")
	else:
		print("Success data change detected")