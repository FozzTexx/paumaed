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
from session import TNFSSession
from datagram import TNFSDatagram, TNFSCommand, TNFSResult
from hexdump import hexdump
import socket
import select
from datetime import datetime
from termcolor import colored

TNFS_VERSION = 0x0102

class TNFSServer:
  def __init__(self, rootDir, port, interface, readonly=False):
    self.rootDir = rootDir
    self.readonly = readonly

    self.sockets = []
    self.socketUDP = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    self.socketUDP.bind((interface, port))
    self.sockets.append(self.socketUDP)

    self.socketTCP = socket.socket(family=socket.AF_INET, type=socket.SOCK_STREAM)
    self.socketTCP.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    self.socketTCP.bind((interface, port))
    self.socketTCP.listen(5)
    self.sockets.append(self.socketTCP)

    self.sessions = {}
    return

  def run(self):
    connections = {}
    while True:
      ready, _, _ = select.select(self.sockets, [], [])
      for sock in ready:
        if sock == self.socketUDP:
          message, address = sock.recvfrom(2048)
        elif sock == self.socketTCP:
          conn, addr = sock.accept()
          connections[conn] = addr
          self.sockets.append(conn)
          continue
        else:
          try:
            message = sock.recv(2048)
          except (OSError, ConnectionResetError):
            message = None
          if not message:
            self.sockets.remove(sock)
            address = connections.pop(sock)
            # Find and remove the session that owns this connection
            dead = [cid for cid, s in self.sessions.items() if s.address == address]
            for cid in dead:
              self.sessions[cid].cleanup()
              del self.sessions[cid]
            continue
          address = connections[sock]

        datagram = TNFSDatagram(message, address)
        print("DATAGRAM", datagram.command, datagram.connID, address)
        hexdump(message)

        self.handleCommand(sock, datagram)
    return

  def handleCommand(self, sock, datagram):
    if datagram.command is None:
      return

    if datagram.command == TNFSCommand.MOUNT:
      self.doMount(sock, datagram)
      return

    reply = TNFSDatagram(datagram)
    reply.result = TNFSResult.INVALID
    session = self.sessions.get(datagram.connID, None)
    if session:
      if datagram.command == TNFSCommand.UMOUNT:
        del self.sessions[session.connID]
        reply.result = TNFSResult.SUCCESS

      elif datagram.command == TNFSCommand.OPENDIR:
        reply.result, reply.handle, _ = session.opendir(datagram.path)

      elif datagram.command == TNFSCommand.OPENDIRX:
        reply.result, reply.handle, reply.count = \
          session.opendir(datagram.path, datagram.dirOptions, datagram.sortOptions,
                          datagram.maxRecords, datagram.wildcard)

      elif datagram.command == TNFSCommand.CLOSEDIR:
        reply.result = session.closedir(datagram.handle)

      elif datagram.command == TNFSCommand.READDIR:
        reply.result, reply.path = session.readdir(datagram.handle)

      elif datagram.command == TNFSCommand.READDIRX:
        reply.result, isLast, records = session.readdirx(datagram.handle, datagram.maxRecords)
        if records:
          # FujiNet can't handle packet larger than 528 bytes, remove
          # records until within that limit
          while True:
            reply.count = len(records[1])
            reply.status = isLast
            reply.dirpos = records[0]
            reply.data = records[1]
            if len(reply.encode()) <= 512:
              break

            # Too many results, try one less
            del records[1][-1]
            isLast = False
            session.seekdir(datagram.handle, session.dirpos(datagram.handle) - 1)

      elif datagram.command == TNFSCommand.SEEKDIR:
        reply.result = session.seekdir(datagram.handle, datagram.position)

      elif datagram.command == TNFSCommand.STAT:
        reply.result, data = session.stat(datagram.path)
        if data is not None:
          for p in data:
            setattr(reply, p, data[p])

      elif datagram.command == TNFSCommand.OPEN:
        if self.readonly \
           and (datagram.flags & TNFSOpenFlags.O_WRONLY.value
                or (datagram.flags & TNFSOpenFlags.O_RDWR.value) == TNFSOpenFlags.O_RDWR.value
                or datagram.flags & TNFSOpenFlags.O_APPEND.value
                or datagram.flags & TNFSOpenFlags.O_CREAT.value
                or datagram.flags & TNFSOpenFlags.O_TRUNC.value):
          reply.result = TNFSResult.EACCESS
          reply.handle = None
        else:
          reply.result, reply.handle = session.open(datagram.path, datagram.flags,
                                                    datagram.mode)

      elif datagram.command == TNFSCommand.CLOSE:
        reply.result = session.close(datagram.handle)

      elif datagram.command == TNFSCommand.READ:
        reply.result, reply.data = session.read(datagram.handle, datagram.length)
        if reply.data is not None:
          reply.length = len(reply.data)

      elif datagram.command == TNFSCommand.WRITE:
        if self.readonly:
          reply.result = TNFSResult.EACCESS
          reply.length = 0
        else:
          reply.result, reply.length = session.write(datagram.handle, datagram.length,
                                                     datagram.data)

      elif datagram.command == TNFSCommand.LSEEK:
        reply.result, reply.position = session.lseek(datagram.handle, datagram.base,
                                                     datagram.offset)

      elif datagram.command == TNFSCommand.MKDIR:
        print("MKDIR not implemented")
        reply.result = TNFSResult.ENOSYS

      elif datagram.command == TNFSCommand.UNLINK:
        reply.result = session.unlink(datagram.path)

      elif datagram.command == TNFSCommand.CHMOD:
        reply.result = session.chmod(datagram.path, datagram.perms)

      else:
        raise NotImplementedError(datagram.command)
        reply.result = TNFSResult.ENOSYS

    else:
      print("NO SESSION", datagram.connID)
      # if datagram.command in (TNFSCommand.READDIR, TNFSCommand.READ):
      #   reply.result = TNFSResult.EOF
      #   reply.length = 0

    result = f"{reply.result}"
    if reply.result != TNFSResult.SUCCESS:
      result = colored(result, "white", on_color="on_red", force_color=True)
    encdata = reply.encode()

    print(datetime.now())
    datagram.print()
    print("RESULT", result)
    reply.print()
    hexdump(encdata)
    print()

    try:
      sock.sendto(encdata, datagram.address)
    except (BrokenPipeError, ConnectionResetError):
      # FIXME - unmount
      pass
    return

  def doMount(self, sock, datagram):
    reply = TNFSDatagram(datagram)
    reply.version = TNFS_VERSION

    already = False
    for connID in self.sessions:
      session = self.sessions[connID]
      if session.location == datagram.location and session.address[0] == datagram.address[0]:
        already = True
        reply.connID = session.connID
        reply.result = TNFSResult.EALREADY
        break

    if not already:
      session = TNFSSession(self, datagram.location, datagram.user, datagram.password)
      if session.connID is None:
        reply.result = TNFSResult.EACCESS
      else:
        reply.connID = session.connID
        reply.retryTime = 5000
        reply.result = TNFSResult.SUCCESS
        session.address = datagram.address
        self.sessions[session.connID] = session

    print(datetime.now())
    datagram.print()
    print(f"RESULT {reply.result}")
    reply.print()
    encdata = reply.encode()
    hexdump(encdata)
    print()
    try:
      sock.sendto(encdata, datagram.address)
    except BrokenPipeError:
      # FIXME - unmount
      pass
    return

  def sanitizePath(self, path):
    if os.path.isabs(path):
      path = os.path.sep.join(path.split(os.path.sep)[1:])
    path = os.path.join(self.rootDir, path)
    path = os.path.normpath(path)
    return path
