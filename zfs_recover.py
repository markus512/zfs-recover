#!/usr/bin/env python3.2

import argparse, os, time, struct, sys

import logging, logging.handlers
log = logging.getLogger('zfs-recover')
log.setLevel(logging.DEBUG)
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter('mailSaver[%(process)s]: %(message)s'))
log.addHandler(handler)

class AnyBlock:
	'''Basic class with common methods.
	_format: formatting conventions for fields, skips field if format is None;
	_magic: magic by which block is detected;
	blocksize: size of the block, pre-set or computed.'''
	__slots__ = frozenset(('_format', '_magic', 'blocksize'))
	_format = {}

	def __eq__(self, other):
		'Compares all fields except private ones.'
		for attr in self.__slots__:
			if attr[0] != '_':
				if getattr(self, attr) != getattr(self, attr):
					return False
		return True

	def descr(self):
		'Prints string describing current block.'
		repr = []
		for attr in self.__slots__:
			if attr[0] != '_':
				value = getattr(self, attr)
				if attr in self._format:
					value = eval(self._format[attr].format(value))
				repr += '{}:{}'.format(attr, value),
		log.info(' '.join(repr))

	def dump(self, block):
		'Prints hexadecimal block data.'
		position = 0
		while position < len(block):
			if len(block) - position > 16:
				data = block[position:position+16]
			else:
				data = block[position:]
			hexes = []
			for x in range(0, len(data)):
				hexes += '{:02X}'.format(data[x]),
			log.info('{:4d}: '.format(position) + ' '.join(hexes[0:8]) + ' : ' + ' '.join(hexes[8:16]) + ' ' + repr(data))
			position += 16

class VdevBootBlock(AnyBlock):
	'''Holds info about vdev:
	offset: ???;
	size: ???;
	version: ???.'''
	__slots__ = frozenset(['version'])
	# I hove no good guides about vdev boot block format now
	#_magic = b'\x0c\xb1\x07\xb0\xf5\x02'
	blocksize = 1 << 13 # 8k

	def __init__(self, block):
		self.version = 0
		log.info('VdevBoot: version:{}'.format(self.version))
		#if not block[0:6] == self._magic:
		#	log.info('VDev magic unrecognized: {}'.format(bytes(block[0:6])))
		#( self.version,
		#	self.offset,
		#	self.size
		#) = struct.unpack('3Q', block[8:32])
		#self.descr()

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
			log.info('UB: version:{} txg:{}'.format(self.version, self.txg))

class NvData(AnyBlock):
	'''Header of the NvList.
	encmethod: encoding method for this nvlist, should be NV_ENCODE_XDR
	endian: host endianess,
	nvflag: ???;
	version: ???.'''
	__slots__ = frozenset(('encmethod', 'endian', '_endians', '_header_size', '_methods', 'nvflag', 'nvpairs', 'version'))
	_endians = {
		0: 'BIG_ENDIAN',
		1: 'LITTLE_ENDIAN',
	}
	_header_size = 12
	_methods = {
		0: 'NV_ENCODE_NATIVE',
		1: 'NV_ENCODE_XDR',
	}
	blocksize = (1 << 17) - (1 << 14) # 128k - 16k

	def __init__(self, block):
		( self.encmethod,
			self.endian,
			# 2 pad of 1 byte
			self.version,
			self.nvflag
		) = struct.unpack('>BB2xII', block[:self._header_size])
		assert self.encmethod in self._methods, 'NvData: incorrect encmethod {}, encodings supported:{}'.format(self.encmethod, repr(self._methods))
		assert self.endian in self._endians, 'NvData: incorrect endian {}, endianess supported: {}'.format(self.endian, repr(self._endians))
		log.info('NvData: version:{} nvflag:{}'.format(self.version, self.nvflag))
		seek = self._header_size
		self.nvpairs = {}
		if self.encmethod == 0: # NV_ENCODE_NATIVE
			log.info('decoding not supported, skipping.')
		else:
			while True:
				nvpair = NvPair(block[seek:])
				if nvpair.encsize == 0:
					break
				self.nvpairs[nvpair.name] = nvpair.data
				seek += nvpair.encsize
		log.info('NvData: ends here')

def nv_align4(number):
	'''aligns number to double words'''
	return (3 + number >> 2) << 2

def decode_string(string):
	'''stripped zero bytes and decodes string'''
	return string.rstrip(b'\x00').decode('ascii')

class NvPair(AnyBlock):
	'''One NvPair record.
	encsize: full size of record with all fields
	decsize: ???;
	namesize: size of the record name
	name: record name
	datatype: type of the stored data
	elements: in case this is array number of its elements'''
	__slots__ = frozenset(('_datatypes', 'data', 'datatype', 'decsize', 'elements', 'encsize', 'namesize', 'name'))
	_datatypes = {
		8: 'DATA_TYPE_UINT64',
		9: 'DATA_TYPE_STRING',
		19: 'DATA_TYPE_NVLIST',
	}

	def __init__(self, block):
		self.blocksize = 0
		( self.encsize,
			self.decsize,
		) = struct.unpack('>II', block[:8])
		if self.encsize == 0:
			return
		self.namesize = nv_align4(struct.unpack('>I', block[8:12])[0])
		data_start = 12 + self.namesize + 4 * 2
		( self.name, 
			self.datatype,
			self.elements,
		) = struct.unpack('>{}sII'.format(self.namesize), block[12:data_start])
		self.name = decode_string(self.name)
		data_format = str(self.encsize - data_start) + 's'
		if self.datatype == 8: # DATA_TYPE_UINT64
			self.data = struct.unpack('>Q', block[data_start:self.encsize])[0]
		elif self.datatype == 9: # DATA_TYPE_STRING
			length = nv_align4(struct.unpack('>I', block[data_start:data_start + 4])[0])
			data_start += 4
			self.data = decode_string(struct.unpack('{}s'.format(length), block[data_start:self.encsize])[0])
		elif self.datatype == 19: # DATA_TYPE_NVLIST
			self.data = NvData(block[data_start:self.encsize])
		else:
			log.info('Unknown datatype: {}, {}.'.format(self.datatype, bytes(block[data_start:self.encsize])))
			raise SystemExit
		log.info('NV: {} {}'.format(self.name, repr(self.data)))

class DVA(AnyBlock):
	'''DVA record.
	'''
	__slots__ = frozenset(('asize', 'birth_txg', 'checksum', 'cksum', 'comp', 'fill', 'gang', 'lsize', 'offset', 'psize', 'type', 'vdev'))
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
	__slots__ = frozenset(('__file', 'cache', 'devsize', 'dvas', 'vdev_label_size', 'vboot', 'uberblocks'))
	vdev_label_size = 1 << 18 # 256k

	def __init__(self, name):
		self.cache = {}
		assert os.access(name, os.R_OK), 'Please specify readable device to work on.'
		self.__file = open(name, 'r+b')
		assert self.__file.seekable(), "Can't seek file."

		# checking device size
		self.devsize = self.__file.seek(0, os.SEEK_END)
		log.info('Detected size: {} bytes.'.format(self.devsize))

		# checking blocks alignment and aligning them accordingly
		vblocks = int(self.devsize / self.vdev_label_size)
		self.uberblocks = {}
		self.vboot = None
		for vdev_addr in (0, self.vdev_label_size, (vblocks - 2) * self.vdev_label_size, (vblocks - 1) * self.vdev_label_size):
			block = self.read(vdev_addr, self.vdev_label_size)
			# checking vboot headers
			vb = VdevBootBlock(block[1 << 13:1 << 14]) # 8k - 16k
			if vb.version >= 0:
				print(repr(self.vboot), repr(vb))
				if type(self.vboot) == type(None):
					self.vboot = vb
				elif self.vboot != vb:
					log.info('Found different VdevBootBlock.')
					log.info('Old:' + self.vboot)
					log.info('New:' + vb)
				# XXX: check nvpairs
				nv = NvData(block[1 << 14:1 << 17]) # 16k - 128k
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
			if len(txgs) > 0:
				last_txg = txgs[0]
				self.dvas = []
				dva_addrs = []
				for dva in self.uberblocks[last_txg].dva:
					#print('Addr:', (dva[1] << 9) + 0x400000, dva[1], 1 << 9)
					dva_block = self.read((dva[1] << 9) + 0x400000, 1 << 7)
					self.dvas += DVA(dva_block),
					dva_addrs += '{:x}'.format(dva[1]),
				log.info('DVA: {}'.format(', '.join(dva_addrs)))

	def read(self, start, size):
		#log.info('Reading {} bytes @0x{:x}.'.format(size, start))
		if start in self.cache:
			#log.info('Start addr hit.')
			if size <= self.cache[start]['size']:
				return(self.cache[start]['block'][0:size])
			else:
				raise KeyError
		else:
			for addr in self.cache:
				if start >= addr and start + size <= addr + self.cache[addr]['size']:
					#log.info('Range hit.')
					return(self.cache[addr][start - addr:start - addr + size])
		#log.info('No hit.')
		self.__file.seek(start)
		block = memoryview(self.__file.read(size))
		self.cache[start] = {
			'size': len(block),
			'block': block,
		}
		return(block)

# For now we need only the device name
parser = argparse.ArgumentParser()
parser.add_argument('-d', '--device', action = 'store', help = 'device to check')
parser.add_argument('-r', '--rollback', action = 'store_true', help = 'ask transaction number to rollback to', default = False)
args = parser.parse_args()

assert args.device != None, 'Please specify device to work on.'
source = SourceDevice(args.device)

# Printing found vdev boot
#print(source.vboot)
# Printing found uberblocks

if args.rollback:
	strip_to = int(input('What transaction you want rollback to? '))

	with open(args.device, '+b') as w_source:
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
