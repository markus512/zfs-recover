#!/usr/bin/env python3.1

# (c) 2010 c.kworr@gmail.com

import io, optparse, os, time, struct

class AnyBlock:
	'Basic class wityh common methods.'
	__slots__ = frozenset(('_format', '_magic', '_name', 'blocksize'))
	_format = {}
	def __eq__(self, other):
		for attr in self.__slots__:
			if attr[-1:] != '_':
				if getattr(self, attr) != getattr(self, attr):
					return False
		return True
	def __repr__(self):
		repr = self._name + ':'
		for attr in self.__slots__:
			if attr[0] != '_':
				value = getattr(self, attr)
				if attr in self._format:
					value = eval(self._format[attr].format(value))
				repr += ' {}:{}'.format(attr, value)
		return(repr)

class VdevBootBlock(AnyBlock):
	'Holds info about this vdev.'
	__slots__ = frozenset(('addr', 'offset', 'size', 'version'))
	_magic = b'\x0c\xb1\x07\xb0\xf5\x02'
	_name = 'VdevBoot'
	blocksize = 1 << 13 # 8k
	def __init__(self, block, address):
		self.addr = (address, )
		self.version = 0
		if block[0:6] == self._magic:
			( self.version,
				self.offset,
				self.size
			) = struct.unpack('QQQ', block[8:32])

class Uberblock(AnyBlock):
	'Holds all info about one uberblock.'
	__slots__ = frozenset(('addr', 'birth', 'dva', 'fill', 'guid_sum', 'pad', 'phys_birth', 'prop', 'timestamp', 'txg', 'version'))
	_format = {
		'timestamp': 'time.strftime("%d %b %Y %H:%M:%S", time.localtime({}))',
	}
	_magic = b'\x0c\xb1\xba\x00' # b10c 00ba, oo-ba bloc!
	_name = 'Uberblock'
	blocksize = 1 << 10 # 1k
	def __init__(self, block, address):
		self.addr = (address, )
		self.version = 0
		self.dva = [0,0]
		self.pad = [0,0]
		if block[0:4] == self._magic:
			( self.version,
				self.txg,
				self.guid_sum,
				self.timestamp,
				self.dva[0],
				self.dva[1],
				self.prop,
				self.pad[0],
				self.pad[1],
				self.phys_birth,
				self.birth,
				self.fill
			) = struct.unpack('QQQQQQQQQQQQ', block[8:104])

class NvData(AnyBlock):
	'Contents of the nvpair list.'
	__slots__ = frozenset(('encmethod', 'endian', '_endians', '_methods', 'nvflag', 'version'))
	_format = {
		'encmethod': 'self._methods[{}]',
		'endian': 'self._endians[{}]',
	}
	_endians = {
		1: 'HOST_ENDIAN_x86',
	}
	_methods = {
		0: 'NV_ENCODE_NATIVE',
		1: 'NV_ENCODE_XDR',
	}
	_name = 'NvData'
	blocksize = (1<<17) - (1<<14) # 128k - 16k
	def __init__(self, block, address):
		( self.encmethod,
			self.endian,
			pad,
			self.version,
			self.nvflag
		) = struct.unpack('BBHII', block[0:12])
		if self.encmethod == 0:
			print('NvData: incorrect format, encoding method unsupported:', self._methods[0])
		elif not self.encmethod in self._methods:
			print('NvData: incorrect fromat, encoding method should be 0 <= x <= 1.')
		if not self.endian in self._endians:
			print('NvData: incorrect fromat, endianess supported:', self._endians[1])
		seek = 12
		while True:
			nvpair = NvPair(block[seek:])
			print(nvpair)
			return

class NvPair(AnyBlock):
	'One NvPair record.'
	__slots__ = frozenset(('decsize', 'encsize', 'namesize'))
	_name = 'NvPair'
	def __init__(self, block):
		self.blocksize = 0
		( self.encsize,
			self.decsize,
			self.namesize,
		) = struct.unpack('IIH', block[0:10])

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
				if type(self.vboot) == type(None):
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
