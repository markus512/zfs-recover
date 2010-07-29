#!/usr/bin/env python3.1

# (c) 2010 c.kworr@gmail.com

import io, optparse, os, time, struct

class VdevBootBlock:
	'Holds info about this vdev.'
	__slots__ = frozenset(('addr', 'blocksize', 'magic', 'offset', 'size', 'version'))
	magic = b'\x0c\xb1\x07\xb0\xf5\x02'
	blocksize = 1 << 13 # 8k
	def __init__(self, source, address):
		block = source.read(address, self.blocksize)
		self.addr = ()
		self.version = 0
		if block[0:6] == self.magic:
			self.version = struct.unpack('Q', block[8:16])[0]
			self.offset = struct.unpack('Q', block[16:24])[0]
			self.size = struct.unpack('Q', block[24:32])[0]
			self.addr += address,
	def __eq__(self, other):
		return(type(other) == type(self) and self.version == other.version and self.offset == other.offset and self.size == other.size)
	def __repr__(self):
		return('VB: addr:{} version:{} offset:{} size:{}'.format(self.addr, self.version, self.offset, self.size))

class Uberblock:
	'Holds all info about one uberblock.'
	__slots__ = frozenset(('addr', 'magic', 'version', 'txg', 'guid_sum', 'timestamp', 'rootbp', 'blocksize'))
	magic = b'\x0c\xb1\xba\x00' # b10c 00ba, oo-ba bloc!
	blocksize = 1 << 10 # 1k
	def __init__(self, source, address):
		block = source.read(address, self.blocksize)
		self.addr = ()
		self.version = 0
		if block[0:4] == self.magic:
			self.version = struct.unpack('Q', block[8:16])[0]
			self.txg = struct.unpack('Q', block[16:24])[0]
			self.guid_sum = struct.unpack('Q', block[24:32])[0]
			self.timestamp = struct.unpack('Q', block[32:40])[0]
			self.rootbp = struct.unpack('Q', block[40:48])[0]
			self.addr += address,
	def __eq__(self, other):
		return(self.version == other.version and self.txg == other.txg and self.guid_sum == other.guid_sum and self.timestamp == other.timestamp and self.rootbp == other.rootbp)
	def __repr__(self):
		return('UB: addr:{} version:{} txg:{} guid_sum:{} timestamp:{} rootbp:{}'.format(self.addr, self.version, self.txg, self.guid_sum, time.strftime("%d %b %Y %H:%M:%S", time.localtime(self.timestamp)), self.rootbp))

class NvData:
	'Contents of the nvpair list.'
	__slots__ = frozenset(('blocksize', 'decsize', 'encmethod', 'endian', 'encsize'))
	blocksize = (1<<17) - (1<<14) # 128k - 16k
	def __init__(self, source, address):
		block = source.read(address, self.blocksize)
		self.encmethod = struct.unpack('B', block[0:1])[0]
		self.endian = struct.unpack('B', block[1:2])[0]
		self.encsize = struct.unpack('I', block[4:8])[0]
		self.decsize = struct.unpack('I', block[8:12])[0]
	def __repr__(self):
		return('NV: encmethod:{} endian:{} encsize:{} decsize:{}'.format(self.encmethod, self.endian, self.encsize, self.decsize))

class SourceDevice:
	__slots__ = frozenset(('__file', 'devsize', 'vdev_label_size', 'vboot', 'uberblocks'))
	vdev_label_size = 1 << 18 # 256k
	def __init__(self, name):
		assert os.access(name, os.R_OK), 'Please specify readable device to work on.'
		self.__file = open(options.device, 'rb')
		assert self.__file.seekable(), "Can't seek file."

		# checking device size
		self.devsize = self.__file.seek(0, os.SEEK_END)
		print('Detected size:', self.devsize, 'bytes.')

		# checking blocks alignment and aligning them accordingly
		vblocks = int(self.devsize / self.vdev_label_size)
		self.uberblocks = {}
		self.vboot = None
		for vdev_addr in (0, self.vdev_label_size, (vblocks - 2) * self.vdev_label_size, (vblocks - 1) * self.vdev_label_size):
			# checking vboot headers
			vboot_addr = vdev_addr + (1 << 13) # 8k
			vb = VdevBootBlock(self, vboot_addr)
			if vb.version > 0:
				if self.vboot == None:
					self.vboot = vb
				elif self.vboot != vb:
					print('Found different VdevBootBlock.')
					print('Old:', self.vboot)
					print('New:', vb)
				else:
					self.vboot.addr += vb.addr
			# XXX: check nvpairs
			#nv = NvData(self, vboot_addr + (1 << 13)) # 8k
			#print(nv)
			# checking uberblocks
			ublocks_addr = vdev_addr + (1 << 17) # 128k
			for ublock_num in range (0, 128):
				ub = Uberblock(self, ublocks_addr + ublock_num * Uberblock.blocksize)
				if ub.version > 0:
					if not ub.txg in self.uberblocks:
						self.uberblocks[ub.txg] = ub
					elif not self.uberblocks[ub.txg] == ub:
						print('Found incorrect uberblock copy.')
						print('Old: ', self.uberblocks[ub.txg])
						print('New: ', ub)
					else:
						self.uberblocks[ub.txg].addr += ub.addr
	def read(self, seek, size):
		self.__file.seek(seek)
		return(self.__file.read(size))

def check_block(block_number, block, uberblocks):
	if len(block) == 0:
		return
	ub = Uberblock(block, block_number)
	if ub.version > 0:
		if not ub.txg in uberblocks:
			uberblocks[ub.txg] = ub
		elif not uberblocks[ub.txg] == ub:
			print('Found incorrect uberblock copy.')
			print('Old: ', uberblocks[ub.txg])
			print('New: ', ub)
		else:
			uberblocks[ub.txg].addr += block_number,
	vb = VdevBootBlock(block, block_number)
	if vb.version > 0:
		print(vb)

# For now we need only the device name
parser = optparse.OptionParser()
parser.add_option('-d', '--device', action = 'store', dest = 'device', help = 'device to check', metavar = 'string')
parser.add_option('-r', '--rollback', action = 'store_true', dest = 'rollback', help = 'ask transaction number to rollback to', metavar = 'bool', default = False)
(options, args) = parser.parse_args()

assert options.device != None, 'Please specify device to work on.'
source = SourceDevice(options.device)

# Printing found vdev boot
print(source.vboot)
# Printing found uberblocks
for txg in source.uberblocks:
	print(source.uberblocks[txg])

if options.rollback:
	strip_to = int(input('What transaction you want rollback to? '))

	with open(options.device, '+b') as w_source:
		first = True
		for txg in source.uberblocks:
			if txg > strip_to:
				if first:
					first = False
					print('Refusing to drop oldest transaction.')
					continue
				for addr in source.uberblocks[txg].addr:
					w_source.seek(addr)
					print('Zeroing address', addr, 'from transaction', txg, '.')
					w_source.write(b'\0' * Uberblock.blocksize)
			if first:
				first = False
