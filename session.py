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

from handle import DirectoryHandle, FileHandle, TNFSDirEntry, TNFSOpenFlags
from datagram import TNFSResult
from hexdump import hexdump
import os
import pwd, grp
import stat
from dataclasses import dataclass

@dataclass
class DirectoryEntry:
  flags: int
  size: int
  mtime: int
  ctime: int
  name: str

class TNFSSession:
  sessionCounter = 0

  def __init__(self, rootDir, location, user, password):
    self.connID = None
    if user or password:
      # FIXME - validate user/pass
      return

    # FIXME - does location exist?
    self.location = rootDir
    path = self.sanitizePath(location)
    if not os.path.exists(path) or not os.path.isdir(path) \
       or not os.access(path, os.R_OK) or not os.access(path, os.X_OK):
      return

    TNFSSession.sessionCounter += 1
    self.connID = TNFSSession.sessionCounter
    self.location = path
    self.handles = {}

    return

  def _allocateHandleID(self):
    for hid in range(1, 256):
      if hid not in self.handles:
        return hid
    return None

  def sanitizePath(self, path):
    if os.path.isabs(path):
      path = os.path.sep.join(path.split(os.path.sep)[1:])
    path = os.path.join(self.location, path)
    path = os.path.normpath(path)
    return path

  def opendir(self, path, dirOptions=None, sortOptions=None, maxRecords=None, wildcard=None):
    path = self.sanitizePath(path)
    print("OPENDIR", path)
    if not os.path.exists(path):
      return TNFSResult.ENOENT, None, None

    if not os.path.isdir(path):
      return TNFSResult.ENOTDIR, None, None

    if not os.access(path, os.R_OK) or not os.access(path, os.X_OK):
      return TNFSResult.EPERM, None, None

    hid = self._allocateHandleID()
    if hid is None:
      return TNFSResult.ENFILE, None, None
    handle = DirectoryHandle(hid, path, dirOptions, sortOptions,
                             maxRecords, wildcard)
    self.handles[handle.handleID] = handle
    return TNFSResult.SUCCESS, handle.handleID, len(handle.contents)

  def closedir(self, handleID):
    if handleID in self.handles:
      del self.handles[handleID]
    return TNFSResult.SUCCESS

  def readdir(self, handleID):
    if handleID not in self.handles:
      return TNFSResult.EBADFD, None
    handle = self.handles[handleID]
    if not isinstance(handle, DirectoryHandle):
      return TNFSResult.EBADFD, None
    val = handle.next()
    if val is None:
      return TNFSResult.EOF, None
    print("READDIR", val)
    return TNFSResult.SUCCESS, val

  def readdirx(self, handleID, maxRecords):
    if handleID not in self.handles:
      return TNFSResult.EBADFD, None, None
    handle = self.handles[handleID]
    if not isinstance(handle, DirectoryHandle):
      return TNFSResult.EBADFD, None

    records = []
    index = handle.index
    while len(records) < maxRecords:
      name = handle.next()
      if name is None:
        break

      fullpath = os.path.join(handle.path, name)
      if os.path.exists(fullpath):
        pstat = os.stat(fullpath)
      else:
        # Must by a symlink to a file that doesn't exist
        pstat = os.lstat(fullpath)
      flags = 0
      if stat.S_ISDIR(pstat.st_mode):
        flags |= TNFSDirEntry.DIR.value
      elif not stat.S_ISREG(pstat.st_mode):
        flags |= TNFSDirEntry.SPECIAL.value
      if name[0] == '.':
        flags |= TNFSDirEntry.HIDDEN.value

      entry = DirectoryEntry(flags, pstat.st_size,
                             int(pstat.st_mtime), int(pstat.st_ctime), name)
      records.append(entry)

    if not records:
      return TNFSResult.EOF, None, None

    return TNFSResult.SUCCESS, handle.index >= len(handle.contents), (index, records)

  def seekdir(self, handleID, position):
    if handleID not in self.handles:
      return TNFSResult.EBADFD, None, None
    handle = self.handles[handleID]

    if position < 0 or position >= len(handle.contents):
      return TNFSResult.EINVAL
    handle.index = position
    return TNFSResult.SUCCESS

  def dirpos(self, handleID):
    if handleID not in self.handles:
      return TNFSResult.EBADFD
    return self.handles[handleID].index

  def stat(self, path):
    path = self.sanitizePath(path)
    if not os.path.exists(path):
      return TNFSResult.ENOENT, None

    pstat = os.stat(path)
    statd = {
      'mode': pstat.st_mode,
      'uid': pstat.st_uid,
      'gid': pstat.st_gid,
      'size': pstat.st_size,
      'atime': int(pstat.st_atime),
      'mtime': int(pstat.st_mtime),
      'ctime': int(pstat.st_ctime),
      'uidstring': pwd.getpwuid(pstat.st_uid)[0],
      'gidstring': grp.getgrgid(pstat.st_gid)[0],
    }
    print("STAT", path, statd)
    return TNFSResult.SUCCESS, statd

  def open(self, path, tnfsFlags, mode):
    path = self.sanitizePath(path)
    if os.path.isdir(path):
      return TNFSResult.EISDIR, None

    # TNFSOpenFlags.O_RDWR is multiple bits, make sure they are all set
    if (tnfsFlags & TNFSOpenFlags.O_RDWR.value) == TNFSOpenFlags.O_RDWR.value:
      print("OPEN RW", tnfsFlags)
      pyflags = os.O_RDWR
    elif tnfsFlags & TNFSOpenFlags.O_WRONLY.value:
      print("OPEN W", tnfsFlags)
      pyflags = os.O_WRONLY
    else:
      print("OPEN R", tnfsFlags)
      pyflags = os.O_RDONLY

    if tnfsFlags & TNFSOpenFlags.O_APPEND.value:
      pyflags |= os.O_APPEND
    if tnfsFlags & TNFSOpenFlags.O_CREAT.value:
      pyflags |= os.O_CREAT
    if tnfsFlags & TNFSOpenFlags.O_EXCL.value:
      pyflags |= os.O_EXCL
    if tnfsFlags & TNFSOpenFlags.O_TRUNC.value:
      pyflags |= os.O_TRUNC

    try:
      print("OPEN", tnfsFlags, pyflags, mode)
      fd = os.open(path, pyflags, mode)
    except FileNotFoundError:
      return TNFSResult.ENOENT, None
    except PermissionError:
      return TNFSResult.EACCESS, None

    hid = self._allocateHandleID()
    if hid is None:
      return TNFSResult.ENFILE, None
    handle = FileHandle(hid, fd)
    self.handles[handle.handleID] = handle
    return TNFSResult.SUCCESS, handle.handleID

  def close(self, handleID):
    if handleID in self.handles:
      handle = self.handles.pop(handleID)
      if isinstance(handle, FileHandle):
        handle.close()
    return TNFSResult.SUCCESS

  def read(self, handleID, length):
    if handleID not in self.handles:
      return TNFSResult.EBADFD, None
    handle = self.handles[handleID]
    if not isinstance(handle, FileHandle):
      return TNFSResult.EBADFD, None
    pos = handle.lseek(os.SEEK_CUR, 0)
    data = handle.read(length)
    track = (pos // 256) // 16
    sector = (pos // 256) % 16
    print("SESSION READ", length, len(data), pos, f"track: {track}  sector: {sector}")
    if not data:
      return TNFSResult.EOF, None
    return TNFSResult.SUCCESS, data

  def write(self, handleID, length, data):
    if length != len(data):
      TNFSResult.EINVAL, None
    if handleID not in self.handles:
      return TNFSResult.EBADFD, None
    handle = self.handles[handleID]
    if not isinstance(handle, FileHandle):
      return TNFSResult.EBADFD, None
    pos = handle.lseek(os.SEEK_CUR, 0)
    wrote = handle.write(data)
    track = (pos // 256) // 16
    sector = (pos // 256) % 16
    print("SESSION WRITE", pos, f"track: {track}  sector: {sector}")
    hexdump(data)
    return TNFSResult.SUCCESS, wrote

  def lseek(self, handleID, base, offset):
    if handleID not in self.handles:
      return TNFSResult.EBADFD, None
    handle = self.handles[handleID]
    if not isinstance(handle, FileHandle):
      return TNFSResult.EBADFD, None
    pos = handle.lseek(base, offset)
    return TNFSResult.SUCCESS, pos

  def unlink(self, path):
    path = self.sanitizePath(path)
    os.remove(path)
    return TNFSResult.SUCCESS

  def chmod(self, path, perms):
    path = self.sanitizePath(path)
    try:
      os.chmod(path, perms)
    except FileNotFoundError:
      return TNFSResult.ENOENT, None
    except PermissionError:
      return TNFSResult.EACCESS, None
    return TNFSResult.SUCCESS

  def cleanup(self):
    for handle in self.handles.values():
      if isinstance(handle, FileHandle):
        handle.close()
    self.handles.clear()
