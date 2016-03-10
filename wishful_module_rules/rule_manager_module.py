import logging
import time
import operator
import datetime
import threading
import Queue
from collections import deque
from stream import ThreadedFeeder, repeatcall, seq, takewhile, dropwhile, maximum, take, filter, map, item
from scapy.all import sniff

import wishful_upis as upis
import wishful_framework as wishful_module
from wishful_framework import CmdDesc, TimeEvent, PktEvent, MovAvgFilter, PeakDetector, Match, Action, Permanance, PktMatch, FieldSelector


__author__ = "Piotr Gawlowicz"
__copyright__ = "Copyright (c) 2015, Technische Universität Berlin"
__version__ = "0.1.0"
__email__ = "{gawlowicz}@tkn.tu-berlin.de"


class FilterContainter(object):
    def __init__(self):
        self.log = logging.getLogger('FilterContainter')
        self.filters = []
        self.sampleNum = 0

    def add_filter(self, myfilter):
        self.filters.append(myfilter)

    def __call__(self, sample):
        self.sampleNum = self.sampleNum + 1
        self.log.debug("Before filtering: {}".format(sample))
        #print "Before filtering: {}".format(sample)
        for f in self.filters:
            if sample:
                sample = f(sample)
            else:
                break
        self.log.debug("\tAfter filtering: {}".format(sample))
        #print "\tAfter filtering: {}".format(sample)
        if sample:
            return sample


class PeakDetectorObj(object):
    def __init__(self, threshold=0):
        self.threshold = threshold

    def __call__(self, sample):
        if sample >= self.threshold:
            return sample


class MovAvgFilterObj(object):
    def __init__(self, length=5):
        self.length = length
        self.samples = deque()

    def __call__(self, sample):
        sample = int(sample)
        self.samples.append(sample)

        if len(self.samples) == self.length:
            s = sum(self.samples)
            self.samples.popleft()
            return s / self.length
        return None


class ActionObject(object):
    def __init__(self, agent, actionDesc):
        self.log = logging.getLogger('ActionObject')
        self.agent = agent
        self.upi_type = actionDesc.upi_type
        self.upi_func = actionDesc.upi_func
        self.kwargs = actionDesc.kwargs
        self.iface = actionDesc.iface

    def __call__(self, sample):
        cmdDesc = CmdDesc()
        cmdDesc.type = self.upi_type
        cmdDesc.func_name = self.upi_func
        cmdDesc.call_id = str(0)
        if self.iface:
            cmdDesc.interface = self.iface
        kwargs = self.kwargs
        msgContainer = ["agent", cmdDesc, kwargs]

        self.log.debug("Rule matched, executing action: {}.{}({})".format(self.upi_type,self.upi_func,self.kwargs))
        response = self.agent.moduleManager.send_cmd_to_module_blocking(msgContainer)
        retVal = response[2]
        return sample


class MatchObject(object):
    def __init__(self, matchDesc):
        self.condition = matchDesc.condition
        self.threshold = matchDesc.value

        self.operator_dict = {}
        self.operator_dict["=="] = lambda x,y : x==y
        self.operator_dict["<>"] = lambda x,y : x!=y
        self.operator_dict["!="] = lambda x,y : x!=y
        self.operator_dict["not"]= lambda x,y : x!=y
        self.operator_dict["~="] = lambda x,y : x!=y
        self.operator_dict[">"] = lambda x,y : x>y
        self.operator_dict[">="] = lambda x,y : x>=y
        self.operator_dict["<"] = lambda x,y : x<y
        self.operator_dict["<="] = lambda x,y : x<=y

    def __call__(self, x):
        return self.operator_dict[self.condition](x, self.threshold)


class UpiEventGenerator(object):
    def __init__(self, agent, eventDesc):
        self.log = logging.getLogger('UpiEventGenerator')
        self._stop = False
        self.agent = agent
        self.eventDesc = eventDesc

    def stop(self):
        self._stop = True

    def __call__(self):
        cmdDesc = CmdDesc()
        cmdDesc.type = self.eventDesc.upi_type
        cmdDesc.func_name = self.eventDesc.upi_func
        cmdDesc.call_id = str(0)
        cmdDesc.interface = self.eventDesc.iface
        kwargs = self.eventDesc.kwargs
        msgContainer = ["agent", cmdDesc, kwargs]

        while not self._stop:
          self.log.debug("Next sample".format())
          # perform UPI call
          response = self.agent.moduleManager.send_cmd_to_module_blocking(msgContainer)
          next_sample = response[2]
          yield next_sample
          if self._stop:
            break
          time.sleep(self.eventDesc.interval)


class PacketGenerator(object):
    def __init__(self, iface, pfilter=None, field_selector=None):
        self.log = logging.getLogger('PacketGenerator')
        self.log.info("start packet generator on iface: {}, packet filter: {}, field selector: {}".format(iface,pfilter,field_selector))
        self._stop = False
        self.queue = Queue.Queue()

        self.iface = iface
        self.pfilter = pfilter
        self.field_selector = field_selector

        self.selector_func = None
        if field_selector:
            header = field_selector.split(".")
            selector_str = "{}:%{}%".format(header[0],field_selector)
            selector_str = "{" +selector_str+"}"
            self.selector_func = lambda x:x.sprintf(selector_str)

        if pfilter:
            self.worker = threading.Thread(target=sniff, kwargs={"iface":iface, "prn":self.ip_monitor_callback, "filter":pfilter})
        else:
            self.worker = threading.Thread(target=sniff, kwargs={"iface":iface, "prn":self.ip_monitor_callback})
        self.worker.setDaemon(True)
        self.worker.start()
        
    def ip_monitor_callback(self, pkt):
        self.queue.put(pkt)

    def stop(self):
        self._stop = True

    def __call__( self):
        while not self._stop:
            try:
                pkt = self.queue.get(block=True, timeout=0.5)
                #field selector
                #TODO: check if field exist
                if self.selector_func:
                    value = self.selector_func(pkt)
                    self.log.debug("Next sample for selector: {} - {}".format(self.field_selector, value))
                    yield value
            except Queue.Empty: 
              pass


class UpiRule(threading.Thread):
    def __init__(self, agent, ruleId, ruleDesc):
        super(UpiRule, self).__init__()
        self.log = logging.getLogger('UpiRule')
        self.agent = agent
        self.id = ruleId
        self.ruleDesc = ruleDesc

        self.myGen = UpiEventGenerator(agent, ruleDesc["event"])
        self.filterContainter = None
        self.match = None
        self.action = None
        self.notify_ctrl = False
        self.permanence = Permanance.PERSISTENT
        self.sink = None

        if "filters" in ruleDesc and ruleDesc["filters"]:
            self.filterContainter = FilterContainter()
            for f in ruleDesc["filters"]:
                if f.filter_type == "MovAvgFilter":
                    myFilter = MovAvgFilterObj(f.window_size)
                    self.filterContainter.add_filter(myFilter)
                elif f.filter_type == "PeakDetector":
                    myFilter = PeakDetectorObj(f.threshold)
                    self.filterContainter.add_filter(myFilter)
        
        if "match" in ruleDesc and ruleDesc["match"]:
            self.match = MatchObject(ruleDesc["match"])

        if "action" in ruleDesc and ruleDesc["action"]:
            self.action = ActionObject(agent, ruleDesc["action"])

        if "notify_ctrl" in ruleDesc and ruleDesc["notify_ctrl"]:
            self.notify_ctrl = True

        if "permanence" in ruleDesc:
            self.permanence = ruleDesc["permanence"]


    def stop(self):
        if self.sink:
            [0,1,2,3,4] >> map(lambda x: x) >> self.sink
        self.myGen.stop()


    def _notify_ctrl(self, sample):
        dest = "controller"
        cmdDesc = CmdDesc()
        cmdDesc.type = "wishful_rule"
        cmdDesc.func_name = "wishful_rule"
        cmdDesc.call_id = str(0)
        cmdDesc.serialization_type = CmdDesc.PICKLE
        msg = sample

        encapsulatedMsg = {"node_uuid":self.agent.uuid, "rule_id":self.id, "msg":msg}
        msgContainer = [dest, cmdDesc, encapsulatedMsg]
        self.agent.send_upstream(msgContainer)


    def run( self ):
        self.log.info("Start rule".format())
        if self.permanence == Permanance.TRANSIENT:
          self.sink = item[:1]
        else:
          self.sink = min

        nop = map(lambda x: x)
        elements = [nop, nop, nop, nop, nop]

        if self.filterContainter:
            elements[0] = map(lambda x: self.filterContainter(x)) 

        #remove None value from pipline
        elements[1] = filter(lambda x: True if x is not None else False) 

        if self.match:
            elements[2] = filter(lambda x: self.match(x)) 

        if self.action:
            elements[3] = map(lambda x: self.action(x)) 

        if self.notify_ctrl:
            elements[4] = map(self._notify_ctrl)

        try:
            self.myGen() >> elements[0] >> elements[1] >> elements[2] >> elements[3] >> elements[4] >> self.sink
        except Exception as e:
            pass

        #if TRANSIENT stop generator
        self.myGen.stop()



class PktRule(threading.Thread):
    def __init__(self, agent, ruleId, ruleDesc):
        super(PktRule, self).__init__()
        self.log = logging.getLogger('PktRule')
        self.agent = agent
        self.id = ruleId
        self.ruleDesc = ruleDesc

        self.iface = None
        self.selector = None
        self.pktMatch = None

        self.event = ruleDesc["event"]
        self.iface = self.event.iface

        if "pktMatch" in ruleDesc and ruleDesc["pktMatch"]:
            pktMatch = ruleDesc["pktMatch"]
            self.pktMatch = pktMatch.matchStr

        if "selector" in ruleDesc and ruleDesc["selector"]:
            selector = ruleDesc["selector"]
            self.selector = selector.field

        self.myGen = PacketGenerator(iface=self.iface, pfilter=self.pktMatch, field_selector=self.selector)
        self.filterContainter = None
        self.match = None
        self.action = None
        self.notify_ctrl = False
        self.permanence = Permanance.PERSISTENT
        self.sink = None

        if "filters" in ruleDesc and ruleDesc["filters"]:
            self.filterContainter = FilterContainter()
            for f in ruleDesc["filters"]:
                if f.filter_type == "MovAvgFilter":
                    myFilter = MovAvgFilterObj(f.window_size)
                    self.filterContainter.add_filter(myFilter)
                elif f.filter_type == "PeakDetector":
                    myFilter = PeakDetectorObj(f.threshold)
                    self.filterContainter.add_filter(myFilter)
        
        if "match" in ruleDesc and ruleDesc["match"]:
            self.match = MatchObject(ruleDesc["match"])

        if "action" in ruleDesc and ruleDesc["action"]:
            self.action = ActionObject(agent, ruleDesc["action"])

        if "notify_ctrl" in ruleDesc and ruleDesc["notify_ctrl"]:
            self.notify_ctrl = True

        if "permanence" in ruleDesc:
            self.permanence = ruleDesc["permanence"]


    def stop(self):
        if self.sink:
            [0,1,2,3,4] >> map(lambda x: x) >> self.sink
        self.myGen.stop()


    def _notify_ctrl(self, sample):
        dest = "controller"
        cmdDesc = CmdDesc()
        cmdDesc.type = "wishful_rule"
        cmdDesc.func_name = "wishful_rule"
        cmdDesc.call_id = str(0)
        cmdDesc.serialization_type = CmdDesc.PICKLE
        msg = sample

        encapsulatedMsg = {"node_uuid":self.agent.uuid, "rule_id":self.id, "msg":msg}
        msgContainer = [dest, cmdDesc, encapsulatedMsg]
        self.agent.send_upstream(msgContainer)


    def run( self ):
        self.log.info("Start rule".format())
        if self.permanence == Permanance.TRANSIENT:
          self.sink = item[:1]
        else:
          self.sink = min

        nop = map(lambda x: x)
        elements = [nop, nop, nop, nop, nop]

        if self.filterContainter:
            elements[0] = map(lambda x: self.filterContainter(x)) 

        #remove None value from pipline
        elements[1] = filter(lambda x: True if x is not None else False) 

        if self.match:
            elements[2] = filter(lambda x: self.match(x)) 

        if self.action:
            elements[3] = map(lambda x: self.action(x)) 

        if self.notify_ctrl:
            elements[4] = map(self._notify_ctrl)

        try:
            self.myGen() >> elements[0] >> elements[1] >> elements[2] >> elements[3] >> elements[4] >> self.sink
        except Exception as e:
            pass

        #if TRANSIENT stop generator
        self.myGen.stop()



@wishful_module.build_module
class RuleManagerModule(wishful_module.AgentModule):
    def __init__(self):
        super(RuleManagerModule, self).__init__()
        self.log = logging.getLogger('RuleManagerModule')

        self.ruleIdGen = 0
        self.rules = {}


    def generate_new_rule_id(self):
        self.ruleIdGen = self.ruleIdGen + 1
        return self.ruleIdGen


    @wishful_module.bind_function(upis.mgmt.add_rule)
    def add_rule(self, ruleDesc):
        ruleId = self.generate_new_rule_id()
        self.log.info("Add rule with ID: {}".format(ruleId))

        event = ruleDesc["event"]
        if event.type == "TimeEvent":
            newRule = UpiRule(self.agent, ruleId, ruleDesc)
            newRule.deamon = True
            newRule.start()
        elif event.type == "PktEvent":
            newRule = PktRule(self.agent, ruleId, ruleDesc)
            newRule.deamon = True
            newRule.start()
        else:
            self.log.debug("Event Type not supported: {}".format(event.type))

        self.rules[ruleId] = newRule
        return ruleId


    @wishful_module.bind_function(upis.mgmt.delete_rule)
    def delete_rule(self, ruleId):
        self.log.info("Delete rule with ID: {}".format(ruleId))
        if ruleId in self.rules:
            rule = self.rules[ruleId]
            rule.stop()
            del self.rules[ruleId]
            return "REMOVED"

        return "NOT_FOUND"


    @wishful_module.on_exit()
    @wishful_module.on_disconnected()
    def remove_all_rules(self):
        self.log.info("Remove all rules".format())
        for ruleId, rule in self.rules.iteritems():
           rule.stop()
        self.rules = {}