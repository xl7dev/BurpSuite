from __future__ import with_statement

from burp import IBurpExtender
from burp import IIntruderPayloadGeneratorFactory
from burp import IIntruderPayloadGenerator
from hashlib import md5
import os
from subprocess import Popen, PIPE

__author__ = 'Raz0r'

radamsa_bin = "radamsa"
payloads_number = 100
temp_dir = '/tmp/radamsa'

class IntruderPayloadGenerator(IIntruderPayloadGenerator):
    indeces = {}
    fresh = True

    def hasMorePayloads(self):
        return True if self.fresh else sum(self.indeces.values()) < len(self.indeces) * payloads_number

    def getNextPayload(self, baseValue):
        payload = ''
        self.fresh = False
        _hash = md5(baseValue).hexdigest()
        index = self.indeces.get(_hash, 0)
        if index == 0:
            if not os.path.exists(temp_dir):
                os.mkdir(temp_dir)
            p = Popen([radamsa_bin, '-n', str(payloads_number), '-o', temp_dir + '/fuzz-' + _hash + '-%n'], stdout=PIPE, \
                  stdin=PIPE, stderr=PIPE)
            p.communicate(input=baseValue)
            p.wait()
        fname = temp_dir + '/fuzz-' + _hash + '-' + str(index+1)
        if os.path.exists(fname):
            with open(fname, "r") as f:
                payload = f.read()
                f.close()
            os.unlink(fname)

        self.indeces.setdefault(_hash, 0)
        self.indeces[_hash]+=1
        return payload

    def reset(self):
        try:
            os.unlink(temp_dir)
        except Exception:
            pass
        self.indeces = {}
        self.fresh = True

class BurpExtender(IBurpExtender, IIntruderPayloadGeneratorFactory):

    def	registerExtenderCallbacks(self, callbacks):

        # obtain an extension helpers object
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName("Radamsa fuzzer")

        callbacks.registerIntruderPayloadGeneratorFactory(self)

        return


    def getGeneratorName(self) :
        return "Radamsa"

    def createNewInstance(self, attack):
        return IntruderPayloadGenerator()


