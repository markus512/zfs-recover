#!/usr/bin/env python3.1

# (c) 2010 c.kworr@gmail.com

import io, optparse, os, time, struct

class AnyBlock:
	'''Basic class with common methods.
	_format: formatting conventions for fields, skips field if format is None;
	_magic: magic by which block is detected;
	_name: name of the structure;
	blocksize: size of the block, pre-set or computed.'''
	__slots__ = frozenset(('_format', '_magic', '_name', 'blocksize'))
	_format = {}

	def __eq__(self, other):
		'Compares all fields except private ones.'
		for attr in self.__slots__:
			if attr[0] != '_':
				if getattr(self, attr) != getattr(self, attr):
					return False
		return True

	def __repr__(self):
		'Returns string describing current block.'
		repr = self._name + ':'
		for attr in self.__slots__:
			if attr[0] != '_':
				value = getattr(self, attr)
				if attr in self._format:
					value = eval(self._format[attr].format(value))
				repr += ' {}:{}'.format(attr, value)
		return(repr)

class VdevBootBlock(AnyBlock):
	'''Holds info about vdev:
	addr: list of copies;
	offset: ???;
	size: ???;
	version: ???.'''
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
			) = struct.unpack('3Q', block[8:32])

class Uberblock(AnyBlock):
	'''Holds info about uberblock. Logically includes not only original uberblock but also its part - blkptr struct.
	addr: list of copies;
	birth: transaction group at block birth;
	dva: three dva adresses, each address needs two long long integers;
	fill: fill count;
	guid_sum: sum of the vdev guids;
	prop: block properties - compression, type, etc;
	timestamp: time when uberblock was writed;
	txg: transaction group;
	version: data format version, suported - 14.'''
	__slots__ = frozenset(('addr', 'birth', 'dva', 'fill', 'guid_sum', 'prop', 'timestamp', 'txg', 'version'))
	_format = {
		'timestamp': 'time.strftime("%d %b %Y %H:%M:%S", time.localtime({}))',
	}
	_magic = b'\x0c\xb1\xba\x00' # b10c 00ba, oo-ba bloc!
	_name = 'Uberblock'
	blocksize = 1 << 10 # 1k

	def __init__(self, block, address):
		self.addr = (address, )
		self.version = 0
		self.dva = [[0, 0], [0, 0], [0, 0]]
		if block[0:4] == self._magic:
			( self.version,
				self.txg,
				self.guid_sum,
				self.timestamp,
				self.dva[0][0],
				self.dva[0][1],
				self.dva[1][0],
				self.dva[1][1],
				self.dva[2][0],
				self.dva[2][1],
				self.prop,
				# 3 pad of 8 bytes
				self.birth,
				self.fill
			) = struct.unpack('QQQQ6QQ24xQQ', block[8:136])
			if self.version != 14:
				print(self._name + ': unknown version, code should be updated to deal with this.', sep = '')

class NvData(AnyBlock):
	'''Header of the NvList.
	encmethod: encoding method for this nvlist, should be NV_ENCODE_XDR
	endian: host endianess,
	nvflag: ???;
	version: ???.'''
	__slots__ = frozenset(('encmethod', 'endian', '_endians', '_methods', 'nvflag', 'nvpairs', 'version'))
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
	blocksize = (1 << 17) - (1 << 14) # 128k - 16k

	def __init__(self, block, address):
		( self.encmethod,
			self.endian,
			# 2 pad of 1 byte
			self.version,
			self.nvflag
		) = struct.unpack('>BB2xII', block[0:12])
		if self.encmethod == 0:
			print('NvData: incorrect format, encoding method unsupported:', self._methods[0])
		elif not self.encmethod in self._methods:
			print('NvData: incorrect fromat, encoding method should be 0 <= x <= 1.')
		if not self.endian in self._endians:
			print('NvData: incorrect fromat, endianess supported:', self._endians[1])
		seek = 12
		self.nvpairs = {}
		while True:
			nvpair = NvPair(block[seek:])
			if nvpair.encsize == 0:
				break
			self.nvpairs[nvpair.name] = nvpair.data
			seek += nvpair.encsize

class NvPair(AnyBlock):
	'''One NvPair record.
	decsize: ???;
	encsize: ???;
	namesize: ???.'''
	__slots__ = frozenset(('data', 'datatype', 'decsize', 'elements', 'encsize', 'namesize', 'name'))
	_name = 'NvPair'
	_datatypes = {
		8: 'DATA_TYPE_UINT64',
		9: 'DATA_TYPE_STRING',
		19: 'DATA_TYPE_NVLIST',
	}

	def __init__(self, block):
		self.blocksize = 0
		( self.encsize,
			self.decsize,
			self.namesize,
		) = struct.unpack('>III', block[0:12])
		if self.encsize > 0:
			self.namesize = (3 + self.namesize >> 2) << 2
			data_start = self.namesize + 20
			( self.name, 
				self.datatype,
				self.elements,
			) = struct.unpack('>{}sII'.format(self.namesize), block[12:data_start])
			self.name = self.name.rstrip(b'\x00').decode('ascii')
			format = str(self.encsize - data_start) + 's'
			if self.datatype == 8: # DATA_TYPE_UINT64
				self.data = struct.unpack('>Q', block[data_start:self.encsize])[0]
			elif self.datatype == 9: # DATA_TYPE_STRING
				format = str((3 + struct.unpack('>I', block[data_start:data_start + 4])[0] >> 2) << 2) + 's'
				data_start += 4
				self.data = struct.unpack(format, block[data_start:self.encsize])[0]
				self.data = self.data.rstrip(b'\x00').decode('ascii')
			else:
				print(self.datatype, block[data_start:self.encsize])

class DVA(AnyBlock):
	'''DVA record.
	'''
	__slots__ = frozenset(('asize', 'birth_txg', 'checksum', 'cksum', 'comp', 'fill', 'gang', 'lsize', 'offset', 'psize', 'type', 'vdev'))
	_name = 'DVA'
	blocksize = 1 << 7 # 128

	def __init__(self, block):
		self.asize = [0, 0, 0]
		asize0 = [0, 0, 0]
		asize1 = [0, 0, 0]
		self.gang = [0, 0, 0]
		goffset = [0, 0, 0]
		self.offset = [0, 0, 0]
		self.vdev = [0, 0, 0]
		self.checksum = [0, 0, 0, 0]
		( self.vdev[0], asize0[0], asize1[0], goffset[0],
			self.vdev[1], asize0[1], asize1[1], goffset[1],
			self.vdev[2], asize0[2], asize1[2], goffset[2],
			#elvl, self.type, self.cksum, self.comp, self.psize, self.lsize,
			self.lsize, self.psize, self.comp, self.cksum, self.type, elvl,
			# 3 pad of 8 bytes
			self.birth_txg,
			self.fill,
			self.checksum[0],
			self.checksum[1],
			self.checksum[2],
			self.checksum[3],
		) = struct.unpack('>IxBHQIxBHQIxBHQHHBBBB24xQQ4Q', block[0:152])
		for x in range(0, 3):
			self.asize[x] = (asize0[x] << 16) + asize1[x]
			if goffset[x] < 0:
				self.gang[x] = True
				self.offset[x] = -goffset[x]
			else:
				self.gang[x] = False
				self.offset[x] = goffset[x]

class SourceDevice:
	'''One device.
	devsize: detected size of the vdev;
	vdev_label_size: size of one vdev label;
	vboot: VdevBootBlock;
	uberblocks: uberblocks list.'''
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
			txgs = list(self.uberblocks.keys())
			txgs.reverse()
			last_txg = txgs[0]
			dvas = ()
			for dva in self.uberblocks[last_txg].dva:
				print('Addr:', (dva[1] << 9) + 0x400000, dva[1], 1 << 9)
				dva_block = self.read((dva[1] << 9) + 0x400000, 1 << 7)
				dvas += DVA(dva_block),
			for dva in dvas:
				print(dva)

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
