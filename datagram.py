##########################################################################
# Copyright 2024 by Chris Osborn <fozztexx@fozztexx.com>
#
# This file is part of paumaed.
#
#  paumaed is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  paumaed is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with paumaed. If not, see <http://www.gnu.org/licenses/>.
##########################################################################

import struct
from enum import Enum
import dataclasses
from hexdump import hexdump

HEADER_FORMAT = "<HBB"
RESULT_FORMAT = "<B"
TNFS_ENDIAN = "<"

class TNFSCommand(Enum):
  MOUNT         = 0x00
  UMOUNT        = 0x01
  OPENDIR       = 0x10
  OPENDIRX      = 0x17
  READDIR       = 0x11
  READDIRX      = 0x18
  TELLDIR       = 0x15
  SEEKDIR       = 0x16
  CLOSEDIR      = 0x12
  MKDIR         = 0x13
  RMDIR         = 0x14
  OPEN          = 0x29
  READ          = 0x21
  WRITE         = 0x22
  CLOSE         = 0x23
  STAT          = 0x24
  LSEEK         = 0x25
  UNLINK        = 0x26
  CHMOD         = 0x27
  RENAME        = 0x28
  SIZE          = 0x30
  FREE          = 0x31

class TNFSResult(Enum):
  SUCCESS	= 0x00
  EPERM 	= 0x01
  ENOENT	= 0x02
  EIO   	= 0x03
  ENXIO 	= 0x04
  E2BIG 	= 0x05
  EBADF 	= 0x06
  EAGAIN	= 0x07
  ENOMEM	= 0x08
  EACCESS	= 0x09
  EBUSY 	= 0x0A
  EEXIST	= 0x0B
  ENOTDIR	= 0x0C
  EISDIR	= 0x0D
  EINVAL	= 0x0E
  ENFILE	= 0x0F
  EMFILE	= 0x10
  EFBIG 	= 0x11
  ENOSPC	= 0x12
  ESPIPE	= 0x13
  EROFS 	= 0x14
  ENAMETOOLONG	= 0x15
  ENOSYS	= 0x16
  ENOTEMPTY	= 0x17
  ELOOP 	= 0x18
  ENODATA	= 0x19
  ENOSTR	= 0x1A
  EPROTO	= 0x1B
  EBADFD	= 0x1C
  EUSERS	= 0x1D
  ENOBUFS	= 0x1E
  EALREADY	= 0x1F
  ESTALE	= 0x20
  EOF   	= 0x21
  INVALID	= 0xFF

  @classmethod
  def fromErrno(cls, errnum):
    _map = {
      errnum.EPERM:        cls.EPERM,
      errnum.ENOENT:       cls.ENOENT,
      errnum.EIO:          cls.EIO,
      errnum.ENXIO:        cls.ENXIO,
      errnum.E2BIG:        cls.E2BIG,
      errnum.EBADF:        cls.EBADFD,
      errnum.EAGAIN:       cls.EAGAIN,
      errnum.ENOMEM:       cls.ENOMEM,
      errnum.EACCES:       cls.EACCESS,
      errnum.EBUSY:        cls.EBUSY,
      errnum.EEXIST:       cls.EEXIST,
      errnum.ENOTDIR:      cls.ENOTDIR,
      errnum.EISDIR:       cls.EISDIR,
      errnum.EINVAL:       cls.EINVAL,
      errnum.ENFILE:       cls.ENFILE,
      errnum.EMFILE:       cls.EMFILE,
      errnum.EFBIG:        cls.EFBIG,
      errnum.ENOSPC:       cls.ENOSPC,
      errnum.ESPIPE:       cls.ESPIPE,
      errnum.EROFS:        cls.EROFS,
      errnum.ENAMETOOLONG: cls.ENAMETOOLONG,
      errnum.ENOSYS:       cls.ENOSYS,
      errnum.ENOTEMPTY:    cls.ENOTEMPTY,
      errnum.ELOOP:        cls.ELOOP,
      errnum.ENOBUFS:      cls.ENOBUFS,
      errnum.ESTALE:       cls.ESTALE,
    }
    return _map.get(errnum, cls.EIO)

COMMAND_FORMAT = {
  TNFSCommand.MOUNT: {
    'input': ("version:H", "location:C", "user:C", "password:C"),
    'output': ("version:H*", "retryTime:H"),
  },
  TNFSCommand.UMOUNT: {
    'input': (),
    'output': (),
  },
  TNFSCommand.OPENDIR: {
    'input': ("path:C", ),
    'output': ("handle:B", ),
  },
  TNFSCommand.OPENDIRX: {
    'input': ("dirOptions:B", "sortOptions:B", "maxRecords:H", "wildcard:C", "path:C", ),
    'output': ("handle:B", "count:H"),
  },
  TNFSCommand.CLOSEDIR: {
    'input': ("handle:B", ),
    'output': (),
  },
  TNFSCommand.READDIR: {
    'input': ("handle:B", ),
    'output': ("path:C", ),
  },
  TNFSCommand.READDIRX: {
    'input': ("handle:B", "maxRecords:B"),
    'output': ("count:B", "status:B", "dirpos:H", "data:ABIIIC", )
  },
  TNFSCommand.SEEKDIR: {
    'input': ("handle:B", "position:I"),
    'output': (),
  },
  TNFSCommand.STAT: {
    'input': ("path:C", ),
    'output': ("mode:H", "uid:H", "gid:H", "size:I", "atime:I", "mtime:I", "ctime:I",
               "uidstring:C", "gidstring:C"),
  },
  TNFSCommand.OPEN: {
    'input': ("flags:H", "mode:H", "path:C"),
    'output': ("handle:B", ),
  },
  TNFSCommand.CLOSE: {
    'input': ("handle:B", ),
    'output': (),
  },
  TNFSCommand.READ: {
    'input': ("handle:B", "length:H"),
    'output': ("length:H*", "data:A"),
  },
  TNFSCommand.WRITE: {
    'input': ("handle:B", "length:H", "data:A"),
    'output': ("length:H", ),
  },
  TNFSCommand.LSEEK: {
    'input': ("handle:B", "base:B", "offset:I"),
    'output': ("position:I", ),
  },
  TNFSCommand.UNLINK: {
    'input': ("path:C", ),
    'output': (),
  },
  TNFSCommand.CHMOD: {
    'input': ("perms:H", "path:C"),
    'output': (),
  },
}

class TNFSDatagram:
  def __init__(self, message, address=None):
    self.address = address
    self.connID = self.retry = self.command = None

    if isinstance(message, TNFSDatagram):
      self.connID = message.connID
      self.retry = message.retry
      self.command = message.command
      return

    self.message = message

    headerSize = struct.calcsize(HEADER_FORMAT)
    if len(self.message) < headerSize:
      return

    self.connID, self.retry, self.command = struct.unpack(HEADER_FORMAT,
                                                          self.message[:headerSize])

    try:
      self.command = TNFSCommand(self.command)
    except ValueError:
      return

    if self.command in COMMAND_FORMAT:
      cmdParse = COMMAND_FORMAT[self.command]['input']
      parmSize = 0
      idx = -1

      fmt = ""
      for parm in cmdParse:
        pos = parm.index(':')
        code = parm[pos+1:]
        fmt += code

      if fmt:
        parms = self.unpack(fmt, self.message[headerSize:])
        fmt = TNFS_ENDIAN + fmt
        #print("PARMS", list(zip(cmdParse, parms)))
        for idx, val in enumerate(parms):
          parm = cmdParse[idx]
          pos = parm.index(':')
          setattr(self, parm[:pos], val)

    return

  def calcentries(self, fmt):
    return len(struct.unpack(fmt, bytearray(struct.calcsize(fmt))))

  def unpack(self, fmt, bdata):
    index = -1
    for special in "CA":
      sidx = fmt.find(special)
      if sidx >= 0 and (sidx < index or index < 0):
        index = sidx

    if index != -1:
      subfmt = fmt[:index]
      data = []
      size = 0
      if subfmt:
        size = struct.calcsize(TNFS_ENDIAN + subfmt)
        data.extend(self.unpack(subfmt, bdata[:size]))
        bdata = bdata[size:]

      if fmt[index] == 'C':
        eos = bdata.index(0)
        data.append(bdata[:eos].decode("UTF8", "replace"))
        bdata = bdata[eos+1:]
      else:
        # FIXME - get length from previous argument somehow? Expect length to be 16bit?
        data.append(bdata)
        bdata = bytearray()

      fmt = fmt[index+1:]
      if fmt:
        data.extend(self.unpack(fmt, bdata))

      return data

    fmt = TNFS_ENDIAN + fmt
    size = struct.calcsize(fmt)
    bdata = bdata[:size]
    return struct.unpack(fmt, bdata)

  def pack(self, fmt, *args, depth=0):
    indent = "--" * depth
    index = -1
    for special in "CA":
      sidx = fmt.find(special)
      if sidx >= 0 and (sidx < index or index < 0):
        index = sidx

    if index != -1:
      prefmt = fmt[:index]
      fmt = fmt[index:]

      data = bytearray()
      count = 0
      if prefmt:
        count = self.calcentries(TNFS_ENDIAN + prefmt)
        data += self.pack(prefmt, *args[:count], depth=depth+1)

      val = args[count]
      if fmt[0] == 'C':
        if not val:
          val = ""
        val = val.encode("UTF8") + b"\0"
        index = 0
      else:
        fmt = fmt[1:]
        index = len(fmt) - 1
        if fmt:
          arr = val
          val = bytearray()
          for elem in arr:
            if dataclasses.is_dataclass(elem):
              fields = dataclasses.fields(elem)
              asdict = dataclasses.asdict(elem)
              elem = [asdict[x.name] for x in fields]
            sval = self.pack(fmt, *elem, depth=depth+1)
            val += sval

      data += val
      fmt = fmt[index+1:]
      if fmt:
        data += self.pack(fmt, *args[count+1:], depth=depth+1)

      return data

    fmt = TNFS_ENDIAN + fmt
    #print("STRUCT PACK", fmt, *args);
    v = struct.pack(fmt, *args)
    #print("SELF PACK", fmt, " ".join([f"{x:02x}" for x in v]))
    return v# struct.pack(fmt, *args)

  def encode(self):
    cv = self.command
    if isinstance(cv, TNFSCommand):
      cv = cv.value
    data = struct.pack(HEADER_FORMAT, self.connID, self.retry, cv)
    if hasattr(self, 'result'):
      data = data + struct.pack(RESULT_FORMAT, self.result.value)

    if self.command not in COMMAND_FORMAT:
      return data

    cmdParse = COMMAND_FORMAT[self.command]['output']
    parms = []

    fmt = ""
    idx = -1
    for idx, parm in enumerate(cmdParse):
      pos = parm.index(':')
      pattr = parm[:pos]
      code = parm[pos+1:]
      required = code[-1] == '*'
      if required:
        code = code[:-1]
      if not required and getattr(self, pattr, None) is None:
        break
      parms.append(getattr(self, pattr, 0))
      fmt += code

    if fmt:
      data = data + self.pack(fmt, *parms)

    # print("ENCODE")
    # hexdump(data)
    return data

  def print(self):
    msglen = -1
    if hasattr(self, 'message'):
      msglen = len(self.message)
    print(f"DATAGRAM Command: {self.command}  Conn: {self.connID}  Seq: {self.retry:02x}"
          f"  Len: {msglen}")
    for key in self.__dict__:
      if key in ("command", "connID", "retry", "message"):
        continue
      val = getattr(self, key)
      if key == "data":
        if isinstance(val, (list, tuple, dict, bytes, bytearray)):
          val = f"{type(val)} of length {len(val)}"
      elif isinstance(val, str):
        val = f"\"{val}\""

      print(f"  {key}: {val}")
    return
