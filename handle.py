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

import os
from enum import Enum
import fnmatch
import glob

class TNFSOpenFlags(Enum):
  O_RDONLY      = 0x0001
  O_WRONLY      = 0x0002
  O_RDWR        = 0x0003
  O_APPEND      = 0x0008
  O_CREAT       = 0x0100
  O_TRUNC       = 0x0200
  O_EXCL        = 0x0400

class TNFSDirEntry(Enum):
  DIR           = 0x01
  HIDDEN        = 0x02
  SPECIAL       = 0x04

class TNFSSeek(Enum):
  SET           = 0
  CUR           = 1
  END           = 2

class DirectoryHandle:
  def __init__(self, handleID, path, dirOptions, sortOptions, maxRecords, wildcard):
    global _handleCounter

    self.handleID = handleID
    # FIXME - validate that path exists and is readable?
    self.path = path
    self.index = 0

    self.loadDirectory(wildcard.startswith("**/"))
    if wildcard:
      self.filterContents(wildcard)
    self.contents.sort(key=str.lower)

    return

  def loadDirectory(self, recursive=False):
    if not recursive:
      self.contents = glob.glob("*", root_dir=self.path)
    else:
      self.contents = []
      for dirpath, dirnames, filenames in os.walk(self.path, followlinks=True):
        for filename in filenames:
          # Join the directory path with the filename to get the full path
          full_path = os.path.join(dirpath, filename)
          rel_path = os.path.relpath(full_path, self.path)
          print(rel_path)
          self.contents.append(rel_path)

    return

  def filterContents(self, pattern):
    if pattern.startswith("**/"):
      pattern = pattern[3:]
    pattern = pattern.lower()
    filtered = []
    for path in self.contents:
      file = os.path.basename(path).lower()
      if fnmatch.fnmatch(file, pattern):
        filtered.append(path)
    self.contents = filtered
    return

  def next(self):
    if self.index >= len(self.contents):
      return None
    val = self.contents[self.index]
    self.index += 1
    return val

class FileHandle:
  def __init__(self, handleID, fd):
    self.handleID = handleID
    self.fd = fd
    return

  def read(self, length):
    return os.read(self.fd, length)

  def write(self, data):
    return os.write(self.fd, data)

  def lseek(self, base, offset):
    whence = os.SEEK_CUR
    if base == TNFSSeek.SET.value:
      whence = os.SEEK_SET
    elif base == TNFSSeek.END.value:
      whence = os.SEEK_END

    return os.lseek(self.fd, offset, whence)

  def close(self):
    os.close(self.fd)
    self.fd = -1
    return
