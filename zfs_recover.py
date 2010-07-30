#!/usr/bin/env python3.1

# (c) 2010 c.kworr@gmail.com

import io, optparse, os, time, struct

class VdevBootBlock:
	'Holds info about this vdev.'
	__slots__ = frozenset(('addr', 'blocksize', 'magic', 'offset', 'size', 'version'))
	magic = b'\x0c\xb1\x07\xb0\xf5\x02'
	blocksize = 1 << 13 # 8k
	def __init__(self, block, address):
		self.addr = ()
		self.version = 0
		if block[0:6] == self.magic:
			self.version = struct.unpack('Q', block[8:16])[0]
			self.offset = struct.unpack('Q', block[16:24])[0]
			self.size = struct.unpack('Q', block[24:32])[0]
			self.addr += address,
	def __eq__(self, other):
		for attr in self.__slots__:
			if not attr in ('addr', 'blocksize', 'magic'):
				if getattr(self, attr) != getattr(self, attr):
					return False
		return True
	def __repr__(self):
		return('VB: addr:{} version:{} offset:{} size:{}'.format(self.addr, self.version, self.offset, self.size))

class Uberblock:
	'Holds all info about one uberblock.'
	__slots__ = frozenset(('addr', 'birth', 'blocksize', 'dva', 'fill', 'guid_sum', 'magic', 'pad', 'phys_birth', 'prop', 'timestamp', 'txg', 'version'))
	magic = b'\x0c\xb1\xba\x00' # b10c 00ba, oo-ba bloc!
	blocksize = 1 << 10 # 1k
	def __init__(self, block, address):
		self.addr = ()
		self.version = 0
		if block[0:4] == self.magic:
			self.version = struct.unpack('Q', block[8:16])[0]
			self.txg = struct.unpack('Q', block[16:24])[0]
			self.guid_sum = struct.unpack('Q', block[24:32])[0]
			self.timestamp = struct.unpack('Q', block[32:40])[0]
			self.dva = struct.unpack('QQ', block[40:56])[0:2]
			self.prop = struct.unpack('Q', block[56:64])[0]
			self.pad = struct.unpack('QQ', block[64:80])[0:2]
			self.phys_birth = struct.unpack('Q', block[80:88])[0]
			self.birth = struct.unpack('Q', block[88:96])[0]
			self.fill = struct.unpack('Q', block[96:104])[0]
			self.addr += address,
	def __eq__(self, other):
		for attr in self.__slots__:
			if not attr in ('addr', 'magic', 'blocksize'):
				if getattr(self, attr) != getattr(self, attr):
					return False
		return True
	def __repr__(self):
		return('UB: addr:{} version:{} txg:{} guid_sum:{} timestamp:{} dva0:{} dva1:{} prop:{} phys_birth:{} birth:{} fill:{}'.format(self.addr, self.version, self.txg, self.guid_sum, time.strftime("%d %b %Y %H:%M:%S", time.localtime(self.timestamp)), self.dva[0], self.dva[1], self.prop, self.phys_birth, self.birth, self.fill))

class NvData:
	'Contents of the nvpair list.'
	__slots__ = frozenset(('blocksize', 'encmethod', 'endian', 'endians', 'methods', 'nvflag', 'version'))
	blocksize = (1<<17) - (1<<14) # 128k - 16k
	endians = {
		1: 'HOST_ENDIAN_x86',
	}
	methods = {
		0: 'NV_ENCODE_NATIVE',
		1: 'NV_ENCODE_XDR',
	}
	def __init__(self, block, address):
		self.encmethod = struct.unpack('B', block[0:1])[0]
		if self.encmethod == 0:
			print('NvData: incorrect format, encoding method unsupported:', self.methods[0])
		elif not self.encmethod in self.methods:
			print('NvData: incorrect fromat, encoding method should be 0 <= x <= 1.')
		self.endian = struct.unpack('B', block[1:2])[0]
		if not self.endian in self.endians:
			print('NvData: incorrect fromat, endianess supported:', self.endians[1])
		self.version = struct.unpack('I', block[4:8])[0]
		self.nvflag = struct.unpack('I', block[8:12])[0]
		seek = 12
		while True:
			nvpair = NvPair(block[seek:])
			print(nvpair)
			return
	def __repr__(self):
		return('ND: encmethod:{} endian:{} version:{} nvflag:{}'.format(self.methods[self.encmethod], self.endians[self.endian], self.version, self.nvflag))

class NvPair:
	'One NvPair record.'
	__slots__ = frozenset(('blocksize', 'decsize', 'encsize', 'namesize'))
	def __init__(self, block):
		self.encsize = struct.unpack('I', block[0:4])[0]
		self.decsize = struct.unpack('I', block[4:8])[0]
		self.namesize = struct.unpack('H', block[4:6])[0]
	def __repr__(self):
		return('NP: encsize:{} decsize:{} namesize:{}'.format(self.encsize, self.decsize, self.namesize))

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
			block = self.read(vdev_addr, self.vdev_label_size)
			# checking vboot headers
			vb = VdevBootBlock(block[1 << 13:1 << 14], vdev_addr + 1 << 13) # 8k - 16k, addr + 8k
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
			nv = NvData(block[1 << 14:1 << 17], vdev_addr + 1 << 14 ) # 16k - 128k, addr + 16k
			print(nv)
			# checking uberblocks
			for ublock_num in range (0, 128):
				start_addr = (1 << 17) + ublock_num * Uberblock.blocksize
				end_addr = (1 << 17) + (ublock_num + 1) * Uberblock.blocksize
				ub = Uberblock(block[start_addr:end_addr], vdev_addr + start_addr)
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
