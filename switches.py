# Copyright (C) 2013 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import six
import struct
import time
from ryu import cfg

from ryu.topology import event
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.exception import RyuException
from ryu.lib import addrconv, hub
from ryu.lib.mac import DONTCARE_STR
from ryu.lib.mac import haddr_to_int
from ryu.lib.dpid import dpid_to_str, str_to_dpid
from ryu.lib.port_no import port_no_to_str
from ryu.lib.packet import packet, ethernet
from ryu.lib.packet import lldp, ether_types
from ryu.ofproto.ether import ETH_TYPE_LLDP
from ryu.ofproto.ether import ETH_TYPE_CFM
from ryu.ofproto import nx_match
from ryu.ofproto import ofproto_v1_0
from ryu.ofproto import ofproto_v1_2
from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ofproto_v1_4
from ryu.lib.mac import haddr_to_bin

from ryu.ofproto import ofproto_common
import threading
import socket
import Queue
import redis
import datetime 

LOG = logging.getLogger(__name__)


CONF = cfg.CONF

CONF.register_cli_opts([
    cfg.BoolOpt('observe-links', default=False,
                help='observe link discovery events.'),
    cfg.BoolOpt('install-lldp-flow', default=True,
                help='link discovery: explicitly install flow entry '
                     'to send lldp packet to controller'),
    cfg.BoolOpt('explicit-drop', default=True,
                help='link discovery: explicitly drop lldp packet in'),
    cfg.StrOpt('environment', default=None, 
                help='you can choose overlay or underlay')
])


class Port(object):
    # This is data class passed by EventPortXXX
    def __init__(self, dpid, ofproto, ofpport):
        super(Port, self).__init__()

        self.dpid = dpid
        self._ofproto = ofproto
        self._config = 0 #ofpport.config
        self._state = 0 #ofpport.state

        self.port_no = ofpport.port_no
        self.hw_addr = ofpport.hw_addr  
        self.name = ofpport.name

        #flows received in this port
        self.in_flows = [] 
        #flows sent out via this port
        self.out_flows = []
        # macs in this port
        self.mac = set()

    def is_reserved(self):
        return self.port_no > self._ofproto.OFPP_MAX

    def is_down(self):
        return (self._state & self._ofproto.OFPPS_LINK_DOWN) > 0 \
            or (self._config & self._ofproto.OFPPC_PORT_DOWN) > 0

    def is_live(self):
        # NOTE: OF1.2 has OFPPS_LIVE state
        #       return (self._state & self._ofproto.OFPPS_LIVE) > 0
        return not self.is_down()

    def to_dict(self):
        return {'dpid': dpid_to_str(self.dpid),
                'port_no': port_no_to_str(self.port_no),
                'hw_addr': self.hw_addr,
                'name': self.name.decode('utf-8')}

    # for Switch.del_port()
    def __eq__(self, other):
        return self.dpid == other.dpid and self.port_no == other.port_no

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.dpid, self.port_no))

    def __str__(self):
        LIVE_MSG = {False: 'DOWN', True: 'LIVE'}
        return 'Port<dpid=%s, port_no=%s, %s>' % \
            (self.dpid, self.port_no, LIVE_MSG[self.is_live()])


class Switch(object):
    # This is data class passed by EventSwitchXXX
    def __init__(self, dp):
        super(Switch, self).__init__()

        self.dp = dp
        self.ports = []

    def add_port(self, ofpport):
        port = Port(self.dp.id, self.dp.ofproto, ofpport)
        if not port.is_reserved():
            self.ports.append(port)

    def del_port(self, ofpport):
        self.ports.remove(Port(ofpport))

    def to_dict(self):
        d = {'dpid': dpid_to_str(self.dp.id),
             'ports': [port.to_dict() for port in self.ports]}
        return d

    def __str__(self):
        msg = 'Switch<dpid=%s, ' % self.dp.id
        for port in self.ports:
            msg += str(port) + ' '

        msg += '>'
        return msg


class Link(object):
    # This is data class passed by EventLinkXXX
    def __init__(self, src, dst):
        super(Link, self).__init__()
        self.src = src
        self.dst = dst

    def to_dict(self):
        d = {'src': self.src.to_dict(),
             'dst': self.dst.to_dict()}
        return d

    # this type is used for key value of LinkState
    def __eq__(self, other):
        return self.src == other.src and self.dst == other.dst

    def __ne__(self, other):
        return not self.__eq__(other)

    def __hash__(self):
        return hash((self.src, self.dst))

    def __str__(self):
        return 'Link: %s to %s' % (self.src, self.dst)


class Host(object):
    # This is data class passed by EventHostXXX
    def __init__(self, mac, port):
        super(Host, self).__init__()
        self.port = port
        self.mac = mac
        self.ipv4 = []
        self.ipv6 = []

    def to_dict(self):
        d = {'mac': self.mac,
             'ipv4': self.ipv4,
             'ipv6': self.ipv6,
             'port': self.port.to_dict()}
        return d

    def __eq__(self, host):
        return self.mac == host.mac and self.port == host.port

    def __str__(self):
        msg = 'Host<mac=%s, port=%s,' % (self.mac, str(self.port))
        msg += ','.join(self.ipv4)
        msg += ','.join(self.ipv6)
        msg += '>'
        return msg


class HostState(dict):
    # mac address -> Host class
    def __init__(self):
        super(HostState, self).__init__()

    def add(self, host):
        mac = host.mac
        self.setdefault(mac, host)

    def update_ip(self, host, ip_v4=None, ip_v6=None):
        mac = host.mac
        host = None
        if mac in self:
            host = self[mac]

        if not host:
            return

        if ip_v4 is not None:
            if ip_v4 in host.ipv4:
                host.ipv4.remove(ip_v4)
            host.ipv4.append(ip_v4)

        if ip_v6 is not None:
            if ip_v6 in host.ipv6:
                host.ipv6.remove(ip_v6)
            host.ipv6.append(ip_v6)

    def get_by_dpid(self, dpid):
        result = []

        for mac in self:
            host = self[mac]
            if host.port.dpid == dpid:
                result.append(host)

        return result


class PortState(dict):
    # dict: int port_no -> OFPPort port
    # OFPPort is defined in ryu.ofproto.ofproto_v1_X_parser
    def __init__(self):
        super(PortState, self).__init__()

    def add(self, port_no, port):
        self[port_no] = port

    def remove(self, port_no):
        del self[port_no]

    def modify(self, port_no, port):
        self[port_no] = port


class PortData(object):
    def __init__(self, is_down, lldp_data):
        super(PortData, self).__init__()
        self.is_down = is_down
        self.lldp_data = lldp_data
        self.timestamp = None
        self.sent = 0

    def lldp_sent(self):
        self.timestamp = time.time()
        self.sent += 1

    def lldp_received(self):
        self.sent = 0

    def lldp_dropped(self):
        return self.sent

    def clear_timestamp(self):
        self.timestamp = None

    def set_down(self, is_down):
        self.is_down = is_down

    def __str__(self):
        return 'PortData<live=%s, timestamp=%s, sent=%d>' \
            % (not self.is_down, self.timestamp, self.sent)


class PortDataState(dict):
    # dict: Port class -> PortData class
    # slimed down version of OrderedDict as python 2.6 doesn't support it.
    _PREV = 0
    _NEXT = 1
    _KEY = 2

    def __init__(self):
        super(PortDataState, self).__init__()
        self._root = root = []  # sentinel node
        root[:] = [root, root, None]  # [_PREV, _NEXT, _KEY] doubly linked list
        self._map = {}

    def _remove_key(self, key):
        link_prev, link_next, key = self._map.pop(key)
        link_prev[self._NEXT] = link_next
        link_next[self._PREV] = link_prev

    def _append_key(self, key):
        root = self._root
        last = root[self._PREV]
        last[self._NEXT] = root[self._PREV] = self._map[key] = [last, root,
                                                                key]

    def _prepend_key(self, key):
        root = self._root
        first = root[self._NEXT]
        first[self._PREV] = root[self._NEXT] = self._map[key] = [root, first,
                                                                 key]

    def _move_last_key(self, key):
        self._remove_key(key)
        self._append_key(key)

    def _move_front_key(self, key):
        self._remove_key(key)
        self._prepend_key(key)

    def add_port(self, port, lldp_data):
        if port not in self:
            self._prepend_key(port)
            self[port] = PortData(port.is_down(), lldp_data)
        else:
            self[port].is_down = port.is_down()

    def lldp_sent(self, port):
        port_data = self[port]
        port_data.lldp_sent()
        self._move_last_key(port)
        return port_data

    def lldp_received(self, port):
        self[port].lldp_received()

    def move_front(self, port):
        port_data = self.get(port, None)
        if port_data is not None:
            port_data.clear_timestamp()
            self._move_front_key(port)

    def set_down(self, port):
        is_down = port.is_down()
        port_data = self[port]
        port_data.set_down(is_down)
        port_data.clear_timestamp()
        if not is_down:
            self._move_front_key(port)
        return is_down

    def get_port(self, port):
        return self[port]

    def del_port(self, port):
        del self[port]
        self._remove_key(port)

    def __iter__(self):
        root = self._root
        curr = root[self._NEXT]
        while curr is not root:
            yield curr[self._KEY]
            curr = curr[self._NEXT]

    def clear(self):
        for node in self._map.values():
            del node[:]
        root = self._root
        root[:] = [root, root, None]
        self._map.clear()
        dict.clear(self)

    def items(self):
        'od.items() -> list of (key, value) pairs in od'
        return [(key, self[key]) for key in self]

    def iteritems(self):
        'od.iteritems -> an iterator over the (key, value) pairs in od'
        for k in self:
            yield (k, self[k])


class LinkState(dict):
    # dict: Link class -> timestamp
    def __init__(self):
        super(LinkState, self).__init__()
        self._map = {}

    def get_peer(self, src):
        return self._map.get(src, None)

    def update_link(self, src, dst):
        link = Link(src, dst)

        self[link] = time.time()
        self._map[src] = dst

        # return if the reverse link is also up or not
        rev_link = Link(dst, src)
        return rev_link in self

    def link_down(self, link):
        del self[link]
        del self._map[link.src]

    def rev_link_set_timestamp(self, rev_link, timestamp):
        # rev_link may or may not in LinkSet
        if rev_link in self:
            self[rev_link] = timestamp

    def port_deleted(self, src):
        dst = self.get_peer(src)
        if dst is None:
            raise KeyError()

        link = Link(src, dst)
        rev_link = Link(dst, src)
        del self[link]
        del self._map[src]
        # reverse link might not exist
        self.pop(rev_link, None)
        rev_link_dst = self._map.pop(dst, None)

        return dst, rev_link_dst


class LLDPPacket(object):
    # make a LLDP packet for link discovery.

    CHASSIS_ID_PREFIX = 'dpid:'
    CHASSIS_ID_PREFIX_LEN = len(CHASSIS_ID_PREFIX)
    CHASSIS_ID_FMT = CHASSIS_ID_PREFIX + '%s'

    PORT_ID_STR = '!I'      # uint32_t
    PORT_ID_SIZE = 4

    class LLDPUnknownFormat(RyuException):
        message = '%(msg)s'

    @staticmethod
    def lldp_packet(dpid, port_no, dl_addr, ttl):
        pkt = packet.Packet()

        dst = lldp.LLDP_MAC_NEAREST_BRIDGE
        src = dl_addr
        ethertype = ETH_TYPE_LLDP
        eth_pkt = ethernet.ethernet(dst, src, ethertype)
        pkt.add_protocol(eth_pkt)

        tlv_chassis_id = lldp.ChassisID(
            subtype=lldp.ChassisID.SUB_LOCALLY_ASSIGNED,
            chassis_id=(LLDPPacket.CHASSIS_ID_FMT %
                        dpid_to_str(dpid)).encode('ascii'))

        tlv_port_id = lldp.PortID(subtype=lldp.PortID.SUB_PORT_COMPONENT,
                                  port_id=struct.pack(
                                      LLDPPacket.PORT_ID_STR,
                                      port_no))

        tlv_ttl = lldp.TTL(ttl=ttl)
        tlv_end = lldp.End()

        tlvs = (tlv_chassis_id, tlv_port_id, tlv_ttl, tlv_end)
        lldp_pkt = lldp.lldp(tlvs)
        pkt.add_protocol(lldp_pkt)

        pkt.serialize()
        return pkt.data

    @staticmethod
    def lldp_parse(data):
        pkt = packet.Packet(data)
        i = iter(pkt)
        eth_pkt = six.next(i)
        assert type(eth_pkt) == ethernet.ethernet

        lldp_pkt = six.next(i)
        if type(lldp_pkt) != lldp.lldp:
            raise LLDPPacket.LLDPUnknownFormat()

        tlv_chassis_id = lldp_pkt.tlvs[0]
        if tlv_chassis_id.subtype != lldp.ChassisID.SUB_LOCALLY_ASSIGNED:
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown chassis id subtype %d' % tlv_chassis_id.subtype)
        chassis_id = tlv_chassis_id.chassis_id.decode('utf-8')
        if not chassis_id.startswith(LLDPPacket.CHASSIS_ID_PREFIX):
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown chassis id format %s' % chassis_id)
        src_dpid = str_to_dpid(chassis_id[LLDPPacket.CHASSIS_ID_PREFIX_LEN:])

        tlv_port_id = lldp_pkt.tlvs[1]
        if tlv_port_id.subtype != lldp.PortID.SUB_PORT_COMPONENT:
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown port id subtype %d' % tlv_port_id.subtype)
        port_id = tlv_port_id.port_id
        if len(port_id) != LLDPPacket.PORT_ID_SIZE:
            raise LLDPPacket.LLDPUnknownFormat(
                msg='unknown port id %d' % port_id)
        (src_port_no, ) = struct.unpack(LLDPPacket.PORT_ID_STR, port_id)

        return src_dpid, src_port_no

class SecurityCheckThread(threading.Thread):
    def __init__(self, func, args):
        threading.Thread.__init__(self)
        self.func = func
        self.args = args
    
    def __call__(self):
        print('====')
        self.result = self.func(*self.args)
 
    def get_result(self):
        try:
            return self.result
        except Exception:
            return None

class Switches(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_0.OFP_VERSION, ofproto_v1_2.OFP_VERSION,
                    ofproto_v1_3.OFP_VERSION, ofproto_v1_4.OFP_VERSION]
    _EVENTS = [event.EventSwitchEnter, event.EventSwitchLeave,
               event.EventSwitchReconnected,
               event.EventPortAdd, event.EventPortDelete,
               event.EventPortModify,
               event.EventLinkAdd, event.EventLinkDelete,
               event.EventHostAdd]

    DEFAULT_TTL = 120  # unused. ignored.
    LLDP_PACKET_LEN = len(LLDPPacket.lldp_packet(0, 0, DONTCARE_STR, 0))

    LLDP_SEND_GUARD = .05
    LLDP_SEND_PERIOD_PER_PORT = .9
    TIMEOUT_CHECK_PERIOD = 5.
    LINK_TIMEOUT = TIMEOUT_CHECK_PERIOD * 2
    LINK_LLDP_DROP = 5

    ENVIRONMENT_WRONG = 1
    SECURE_LINK = 2
    FAKE_LINK = 0
    OTHER_ERROR = 3
    CHECKING = 4

    OVERLAY_SECURE = 1
    OVERLAY_INSECURE = 0

    def __init__(self, *args, **kwargs):
        super(Switches, self).__init__(*args, **kwargs)

        self.name = 'switches'
        self.dps = {}                 # datapath_id => Datapath class
        self.port_state = {}          # datapath_id => ports
        self.ports = PortDataState()  # Port class -> PortData class
        self.links = LinkState()      # Link class -> timestamp
        self.hosts = HostState()      # mac address -> Host class list
        self.is_active = True
        self.link_security_check = {}  #record the hw of the port being checked.

        self.link_discovery = self.CONF.observe_links
        self.mac_to_in_port = {}
        if self.link_discovery:
            self.install_flow = self.CONF.install_lldp_flow
            self.explicit_drop = self.CONF.explicit_drop
            self.lldp_event = hub.Event()
            self.link_event = hub.Event()
            self.threads.append(hub.spawn(self.lldp_loop))
            self.threads.append(hub.spawn(self.link_loop))

    def close(self):
        self.is_active = False
        if self.link_discovery:
            self.lldp_event.set()
            self.link_event.set()
            hub.joinall(self.threads)

    def _register(self, dp):
        assert dp.id is not None

        self.dps[dp.id] = dp
        if dp.id not in self.port_state:
            self.port_state[dp.id] = PortState()
            for port in dp.ports.values():
                self.port_state[dp.id].add(port.port_no, port)

    def _unregister(self, dp):
        if dp.id in self.dps:
            if (self.dps[dp.id] == dp):
                del self.dps[dp.id]
                del self.port_state[dp.id]

    def _get_switch(self, dpid):
        if dpid in self.dps:
            switch = Switch(self.dps[dpid])
            for ofpport in self.port_state[dpid].values():
                switch.add_port(ofpport)
            return switch

    def _get_port(self, dpid, port_no):
        switch = self._get_switch(dpid)
        if switch:
            for p in switch.ports:
                if p.port_no == port_no:
                    return p

    def _port_added(self, port):
        lldp_data = LLDPPacket.lldp_packet(
            port.dpid, port.port_no, port.hw_addr, self.DEFAULT_TTL)
        self.ports.add_port(port, lldp_data)
        # LOG.debug('_port_added dpid=%s, port_no=%s, live=%s',
        #           port.dpid, port.port_no, port.is_live())

    def _link_down(self, port):
        try:
            dst, rev_link_dst = self.links.port_deleted(port)
        except KeyError:
            # LOG.debug('key error. src=%s, dst=%s',
            #           port, self.links.get_peer(port))
            return
        link = Link(port, dst)
        self.send_event_to_observers(event.EventLinkDelete(link))
        if rev_link_dst:
            rev_link = Link(dst, rev_link_dst)
            self.send_event_to_observers(event.EventLinkDelete(rev_link))
        self.ports.move_front(dst)

    def _is_edge_port(self, port):
        for link in self.links:
            if port == link.src or port == link.dst:
                return False

        return True

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        assert dp is not None
        LOG.debug(dp)

        if ev.state == MAIN_DISPATCHER:
            dp_multiple_conns = False
            if dp.id in self.dps:
                LOG.warning('Multiple connections from %s', dpid_to_str(dp.id))
                dp_multiple_conns = True
                (self.dps[dp.id]).close()

            self._register(dp)
            switch = self._get_switch(dp.id)
            LOG.debug('register %s', switch)

            if not dp_multiple_conns:
                self.send_event_to_observers(event.EventSwitchEnter(switch))
            else:
                evt = event.EventSwitchReconnected(switch)
                self.send_event_to_observers(evt)

            if not self.link_discovery:
                return

            if self.install_flow:
                ofproto = dp.ofproto
                ofproto_parser = dp.ofproto_parser

                # TODO:XXX need other versions
                if ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
                    rule = nx_match.ClsRule()
                    rule.set_dl_dst(addrconv.mac.text_to_bin(
                                    lldp.LLDP_MAC_NEAREST_BRIDGE))
                    rule.set_dl_type(ETH_TYPE_LLDP)
                    actions = [ofproto_parser.OFPActionOutput(
                        ofproto.OFPP_CONTROLLER, self.LLDP_PACKET_LEN)]
                    dp.send_flow_mod(
                        rule=rule, cookie=0, command=ofproto.OFPFC_ADD,
                        idle_timeout=0, hard_timeout=0, actions=actions,
                        priority=0xFFFF)
                elif ofproto.OFP_VERSION >= ofproto_v1_2.OFP_VERSION:
                    match = ofproto_parser.OFPMatch(
                        eth_type=ETH_TYPE_LLDP,
                        eth_dst=lldp.LLDP_MAC_NEAREST_BRIDGE)
                    # OFPCML_NO_BUFFER is set so that the LLDP is not
                    # buffered on switch
                    parser = ofproto_parser
                    actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                                      ofproto.OFPCML_NO_BUFFER
                                                      )]
                    inst = [parser.OFPInstructionActions(
                            ofproto.OFPIT_APPLY_ACTIONS, actions)]
                    mod = parser.OFPFlowMod(datapath=dp, match=match,
                                            idle_timeout=0, hard_timeout=0,
                                            instructions=inst,
                                            priority=0xFFFF)
                    dp.send_msg(mod)
                else:
                    LOG.error('cannot install flow. unsupported version. %x',
                              dp.ofproto.OFP_VERSION)

            # Do not add ports while dp has multiple connections to controller.
            if not dp_multiple_conns:
                for port in switch.ports:
                    if not port.is_reserved():
                        self._port_added(port)

            self.lldp_event.set()

        elif ev.state == DEAD_DISPATCHER:
            # dp.id is None when datapath dies before handshake
            if dp.id is None:
                return

            switch = self._get_switch(dp.id)
            if switch:
                if switch.dp is dp:
                    self._unregister(dp)
                    LOG.debug('unregister %s', switch)
                    evt = event.EventSwitchLeave(switch)
                    self.send_event_to_observers(evt)

                    if not self.link_discovery:
                        return

                    for port in switch.ports:
                        if not port.is_reserved():
                            self.ports.del_port(port)
                            self._link_down(port)
                    self.lldp_event.set()

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        reason = msg.reason
        dp = msg.datapath
        ofpport = msg.desc

        if reason == dp.ofproto.OFPPR_ADD:
            # LOG.debug('A port was added.' +
            #           '(datapath id = %s, port number = %s)',
            #           dp.id, ofpport.port_no)
            self.port_state[dp.id].add(ofpport.port_no, ofpport)
            self.send_event_to_observers(
                event.EventPortAdd(Port(dp.id, dp.ofproto, ofpport)))

            if not self.link_discovery:
                return

            port = self._get_port(dp.id, ofpport.port_no)
            if port and not port.is_reserved():
                self._port_added(port)
                self.lldp_event.set()

        elif reason == dp.ofproto.OFPPR_DELETE:
            # LOG.debug('A port was deleted.' +
            #           '(datapath id = %s, port number = %s)',
            #           dp.id, ofpport.port_no)
            self.send_event_to_observers(
                event.EventPortDelete(Port(dp.id, dp.ofproto, ofpport)))

            if not self.link_discovery:
                return

            port = self._get_port(dp.id, ofpport.port_no)
            if port and not port.is_reserved():
                self.ports.del_port(port)
                self._link_down(port)
                self.lldp_event.set()

            self.port_state[dp.id].remove(ofpport.port_no)

        else:
            assert reason == dp.ofproto.OFPPR_MODIFY
            # LOG.debug('A port was modified.' +
            #           '(datapath id = %s, port number = %s)',
            #           dp.id, ofpport.port_no)
            self.port_state[dp.id].modify(ofpport.port_no, ofpport)
            self.send_event_to_observers(
                event.EventPortModify(Port(dp.id, dp.ofproto, ofpport)))

            if not self.link_discovery:
                return

            port = self._get_port(dp.id, ofpport.port_no)
            if port and not port.is_reserved():
                if self.ports.set_down(port):
                    self._link_down(port)
                self.lldp_event.set()

    @staticmethod
    def _drop_packet(msg):
        buffer_id = msg.buffer_id
        if buffer_id == msg.datapath.ofproto.OFP_NO_BUFFER:
            return

        dp = msg.datapath
        # TODO:XXX
        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            dp.send_packet_out(buffer_id, msg.in_port, [])
        elif dp.ofproto.OFP_VERSION >= ofproto_v1_2.OFP_VERSION:
            dp.send_packet_out(buffer_id, msg.match['in_port'], [])
        else:
            LOG.error('cannot drop_packet. unsupported version. %x',
                      dp.ofproto.OFP_VERSION)

    def send_check_command(self, addr_to_config, dst_ip, dst_port, duplex, queue, timestamp):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #s.bind(src_ip, src_port)
        addr = (dst_ip, dst_port)
        data = 'Mark>SecurityCheck,'
        #print('------------')
        data += "timestamp>" + timestamp + ","
        data += 'mac>' + addr_to_config + ',' + 'duplex>' + duplex
        
        s.sendto(data, addr)
        #self.logger.info("sent")
        reply = s.recvfrom(1024)
        #self.logger.info("received")
        #self.logger.info(reply)
        while timestamp not in reply[0]:
            self.logger.info("[func:send_check_command]reply:%s", reply[0])
            self.logger.info("[func:send_check_command]timestamp %s wrong", timestamp)
            reply, __ = s.recvfrom(1024)
            if timestamp in reply:
                break
            t = str(datetime.datetime.now())
            delay = float(t - timestamp)
            if delay > 500000:
                queue.put(0)
                return
            
        if "OK" in reply[0]:
            self.logger.info("[func:send_check_command] OK")
            queue.put(1)
        else:
            self.logger.info("[func:send_check_command] WRONG")
            queue.put(0)
        s.close()

    def start_check(self, addr_to_config, dst_ip, dst_port, queue, timestamp):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        #s.bind(src_ip, src_port)
        addr = (dst_ip, dst_port)
        data = 'Mark>BeginCheck,'
        data += "timestamp>" + timestamp + ","
        #data += 'mac:' + addr_to_config + ',' + 'timeout:' + str(self.LLDP_SEND_PERIOD_PER_PORT)
        #data += 'timeout:' + str(self.LLDP_SEND_PERIOD_PER_PORT)
        data += "timeout>300"
        s.sendto(data, addr)
        #self.logger.info("sent")
        reply = s.recvfrom(1024)
        #self.logger.info("received")
        #self.logger.info(reply)
        while timestamp not in reply[0]:
            self.logger.info("[func:start_check]reply:%s", reply)
            self.logger.info("[func:start_check]timestamp %s wrong", timestamp)
            reply, __ = s.recvfrom(1024)
            if timestamp in reply:
                break
            t = str(datetime.datetime.now())
            delay = float(t - timestamp)
            if delay > 500000:
                queue.put(0)
                return
            
        if "OK" in reply[0]:
            self.logger.info("[func:start_check] OK")
            queue.put(1)
        else:
            self.logger.info("[func:start_check] WRONG")
            queue.put(0)
        s.close()
        #print('release reply: %s', reply)


    def underlay_security_check(self, port1, port2, timestamp):
        #self.logger.info("----------------")
        if not CONF.ofp_tcp_listen_port:
            src_port = ofproto_common.OFP_TCP_PORT
        else:
            src_port = CONF.ofp_tcp_listen_port
        src_ip = CONF.ofp_listen_host
        LOG.debug(src_port)
        src_port += 1
        LOG.debug('ip:%s', src_ip)
        

        dp1 = self.dps.get(port1.dpid, None)
        if dp1 is None:
            LOG.error('Get datapath from port %s failed', port1)
            return self.OTHER_ERROR
        dp2 = self.dps.get(port2.dpid, None)
        if dp2 is None:
            LOG.error('Get datapath from port %s failed', port2)
            return self.OTHER_ERROR

        socket1 = dp1.socket
        socket2 = dp2.socket
        if not socket1 or not socket2:
            LOG.error('No available socket')
            return self.OTHER_ERROR

        ip1, tcp_port1 = socket1.getpeername()
        ip2, tcp_port2 = socket2.getpeername()
        #timestamp = str(datetime.datetime.now())
        #timestamp = timestamp.replace(" ", "")
        timestamp = timestamp
        #self.logger.info("[func: underlay_security_detection] timestamp:%s", timestamp)
        #print(ip1)
        #print(tcp_port1)

        q1 = Queue.Queue()
        q2 = Queue.Queue()
        #self.logger.info("timestamp:%s, send command begin at %s", timestamp, str(datetime.datetime.now()))
        send_begin_time = datetime.datetime.now()
        #t1 = threading.Thread(target = self.send_check_command, args = (port1.hw_addr, ip1, tcp_port1, 'half', q1))
        #t2 = threading.Thread(target = self.send_check_command, args = (port2.hw_addr, ip2, tcp_port2, 'full', q2))
        t1 = threading.Thread(target = self.send_check_command, args = (port1.hw_addr, "10.15.123.124", tcp_port1, 'half', q1, timestamp))
        t2 = threading.Thread(target = self.send_check_command, args = (port2.hw_addr, "10.15.123.128", tcp_port2, 'full', q2, timestamp))
        t1.start()
        t2.start()

        t1.join()
        t2.join()
          
        res1 = q1.get()
        res2 = q2.get()
        send_end_time = datetime.datetime.now()
        send_time = str(send_end_time - send_begin_time)
        #self.query_redis("send_time", send_time[-6:], "lpush")
        #self.logger.info("timestamp:%s, send command end at %s", timestamp, str(datetime.datetime.now()))
        if res1 and res2: #duplex set finished
            nq1 = Queue.Queue()
            nq2 = Queue.Queue()
            start_begin_time = datetime.datetime.now()
            #self.logger.info("timestamp:%s, start check begin at %s", timestamp, str(datetime.datetime.now()))
            #nt1 = threading.Thread(target = self.start_check, args = (port1.hw_addr, ip1, tcp_port1, nq1))
            #nt2 = threading.Thread(target = self.start_check, args = (port2.hw_addr, ip2, tcp_port2, nq2))
            nt1 = threading.Thread(target = self.start_check, args = (port1.hw_addr, "10.15.123.124", tcp_port1, nq1, timestamp))
            nt2 = threading.Thread(target = self.start_check, args = (port2.hw_addr, "10.15.123.128", tcp_port2, nq2, timestamp))
            nt1.start()
            nt2.start()

            nt1.join()
            nt2.join()

            nres1 = nq1.get()
            nres2 = nq2.get()
            start_end_time = datetime.datetime.now()
            start_time = str(start_end_time - start_begin_time)
            
            #self.logger.info("timestamp:%s, start check end at %s", timestamp, str(datetime.datetime.now()))
            #self.logger.info("nres2: ")
            #self.logger.info(nres2)
            if nres2:  #nres1 for send, nres2 for receive
                #self.query_redis("genuine_start_time", start_time[-6:], "lpush")
                self.logger.info("Genuine link detected:%s<->%s, timestamp:%s", port1.name, port2.name, timestamp)
                return self.SECURE_LINK
            else:
                #self.query_redis("malicious_start_time", start_time[-6:], "lpush")
                self.logger.info("Faked link detected:%s<->%s, timestamp:%s", port1.name, port2.name, timestamp)
                return self.FAKE_LINK
        else:
            return self.FAKE_LINK

    def stop_receiving(self, msg, match_eth_type = 0x0800):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if msg.datapath.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            in_port = msg.in_port
            macth = parser.OFPMatch(in_port = in_port)
        elif msg.datapath.ofproto.OFP_VERSION >= ofproto_v1_2.OFP_VERSION:
            in_port = msg.match['in_port']
            match = parser.OFPMatch(eth_type = match_eth_type, in_port = in_port)
        
        instruction = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(datapath = datapath, 
                                    priority = 32768, 
                                    table_id = 0,
                                    match = match, 
                                    command=ofproto.OFPFC_ADD,
                                    buffer_id = msg.buffer_id,
                                    instructions = instruction)
        else:
            mod = parser.OFPFlowMod(datapath = datapath, 
                                    priority = 32768, 
                                    match = match, 
                                    table_id = 0,
                                    command=ofproto.OFPFC_ADD,
                                    instructions = instruction)
        datapath.send_msg(mod)
        return 

    def start_receiving(self, msg, match_eth_type = 0x0800):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        if msg.datapath.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            in_port = msg.in_port
            macth = parser.OFPMatch(in_port = in_port)
        elif msg.datapath.ofproto.OFP_VERSION >= ofproto_v1_2.OFP_VERSION:
            in_port = msg.match['in_port']
            match = parser.OFPMatch(eth_type = match_eth_type, in_port = in_port)

        instruction = [parser.OFPInstructionActions(ofproto.OFPIT_CLEAR_ACTIONS, [])]
        if msg.buffer_id != ofproto.OFP_NO_BUFFER:
            mod = parser.OFPFlowMod(datapath = datapath, 
                                    priority = 32768, 
                                    table_id = 0,
                                    match = match, 
                                    out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                                    command=ofproto.OFPFC_DELETE)
        else:
            mod = parser.OFPFlowMod(datapath = datapath, 
                                    priority = 32768, 
                                    match = match, 
                                    table_id = 0,
                                    out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                                    command=ofproto.OFPFC_DELETE)
        datapath.send_msg(mod)
        return

    def overlay_security_check(self, src, dst, msg):
        checked_times = self.link_security_check.get(src.hw_addr)
        if checked_times == None:
            #LOG.debug('stopping receiving')
            self.stop_receiving(msg)
            self.link_security_check[src.hw_addr] = 1
            self.send_lldp_packet(src)
            # In overlay network, the lldp packet may by encapsulated and send via src port to the dst port, thus must forbid it temporarily
            return self.CHECKING
        else:
            # Have stopped sending out packets via src port, but still receive the lldp packets via src, so it is safe
            #LOG.debug('starting receiving')
            self.start_receiving(msg)
            self.link_security_check.pop(src.hw_addr)
            return self.SECURE_LINK

    #

    def new_link_security_check(self, src, dst, msg):
        #LOG.debug('Starting new_link_security_check func')
        if CONF.environment == 'underlay':
            return self.underlay_security_check(src, dst)

        elif CONF.environment == 'overlay':
            return self.overlay_security_check(src, dst, msg)
            #return self.new_overlay_security_check(src, dst, msg)

        else:
            return self.ENVIRONMENT_WRONG


    def add_flow(self, datapath, in_port, dst, src, actions):
        ofproto = datapath.ofproto

        match = datapath.ofproto_parser.OFPMatch(
            in_port=in_port,
            dl_dst=haddr_to_bin(dst), dl_src=haddr_to_bin(src))

        mod = datapath.ofproto_parser.OFPFlowMod(
            datapath=datapath, match=match, cookie=0,
            command=ofproto.OFPFC_ADD, idle_timeout=0, hard_timeout=0,
            priority=ofproto.OFP_DEFAULT_PRIORITY,
            flags=ofproto.OFPFF_SEND_FLOW_REM, actions=actions)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg  
        datapath = msg.datapath
        ofproto = datapath.ofproto

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return
        dst = eth.dst
        src = eth.src

        dpid = datapath.id
        self.mac_to_in_port.setdefault(dpid, {})

        self.logger.info("packet in %s %s %s %s", dpid, src, dst, msg.in_port)

        # learn a mac address to avoid FLOOD next time.
        self.mac_to_in_port[dpid][src] = msg.in_port

        if dst in self.mac_to_in_port[dpid]:
            out_port = self.mac_to_in_port[dpid][dst]
            self.logger.info("action our_port")
        else:
            out_port = ofproto.OFPP_FLOOD
            self.logger.info("action flood")

        actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]

        # install a flow to avoid packet_in next time
        if out_port != ofproto.OFPP_FLOOD:
            self.add_flow(datapath, msg.in_port, dst, src, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = datapath.ofproto_parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=msg.in_port,
            actions=actions, data=data)
        datapath.send_msg(out)
    
    def query_redis(self, name, value, command):
        if command == "add":
            r = redis.Redis(host = "127.0.0.1", port = 6379)
            res = r.sadd(name, value)
            return res
        elif command == "query":
            r = redis.Redis(host = "127.0.0.1", port = 6379)
            res = r.sismember(name, value)
            return res
        elif command == "lpush":
            r = redis.Redis(host = "127.0.0.1", port = 6379)
            res = r.lpush(name, value)
            return res

    def overlay_security_detection(self, flow, port):
        flag = 0
        opposite_port_no = -1
        opposize_dpid = -1
        for link in self.links:
            if port == link.src:
                opposite_port_no = link.dst.port_no
                opposize_dpid = link.dst.dpid
                flag = 1
                break
            if port == link.dst:
                opposite_port_no = link.src.port_no
                opposize_dpid = link.src.dpid
                flag = 1
                break
        if flag == 0: # it may be the edge switch
            new_host = Host(flow[0], port)
            #self.logger.info(flow[0])
            for host in self.hosts.values():
                #self.logger.info("new:%s", host.mac)
                if host.__eq__(new_host):
                    #self.logger.info("find existing host mac:%s, port:%s", host.mac, host.port.name)
                    #self.logger.info("Correct flow on edge port %s", port.name)
                    return self.OVERLAY_SECURE # edge switch
            self.logger.info("Suspicious flow on edge port %s from %s", port.name, flow[0])
            return self.OVERLAY_INSECURE # wrong
        opposize_port = self._get_port(opposize_dpid, opposite_port_no)
        #self.logger.info("potential opposize port detected: %s, dpid:%s, portno%s", opposize_port.name, opposize_port.dpid, opposize_port.port_no)
        name = opposize_port.name + "out"
        value = ""
        for i in flow:
            value += str(i)
        if self.query_redis(name, value, "query"):
            #self.logger.info("potential opposize port %s is correct", opposize_port.name)
            return self.OVERLAY_SECURE
        else:
            self.logger.info("Suspicious flow on port %s from %s", port.name, flow[0])
            return self.OVERLAY_INSECURE   

        
    #@set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def graph_construction(self, msg):
        t1 = datetime.datetime.now()
        eth, pkt_type, pkt_data = ethernet.ethernet.parser(msg.data)
        if eth.ethertype in (ETH_TYPE_LLDP, ETH_TYPE_CFM):
            return
        
        src_mac = eth.src
        datapath = msg.datapath
        dpid = datapath.id
        port_no = -1

        if msg.datapath.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            port_no = msg.in_port
        else:
            port_no = msg.match['in_port']

        port = self._get_port(dpid, port_no)
        
        port.mac.add(src_mac) 
        
        new_flow = []
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            new_flow.append(src_mac)
            dst_mac = eth.dst
            new_flow.append(dst_mac)
            proto = "ARP"
            new_flow.append(proto)
            #self.logger.info("flow src_mac:%s, dst_mac:%s, proto:%s detected on %s", src_mac, dst_mac, proto, port.name)
        elif eth.ethertype == ether_types.ETH_TYPE_IP:
            new_flow.append(src_mac)
            dst_mac = eth.dst
            new_flow.append(dst_mac)

            ipv4_pkt, _, _ = pkt_type.parser(pkt_data)
            src_ip = ipv4_pkt.src
            new_flow.append(src_ip)
            dst_ip = ipv4_pkt.dst
            new_flow.append(dst_ip)

            proto = ipv4_pkt.proto
            new_flow.append(proto)
            #self.logger.info("flow src_mac:%s, dst_mac:%s, src_ip:%s, dst_ip:%s, proto:%s detected on %s", src_mac, dst_mac, src_ip, dst_ip, proto, port.name)
        else:
            return 
        
        detect_time = ""
        if CONF.environment == "overlay":
            #self.logger.info("overlay detection begins.")
            detect_t1 = datetime.datetime.now()
            res = self.overlay_security_detection(new_flow, port)
            detect_t2 = datetime.datetime.now()
            detect_time = str(detect_t2 - detect_t1)
            if res == self.OVERLAY_INSECURE:
                #self.logger.info('Malicious packet detected on! src_mac:%s, dst_mac:%s, proto:%s', src_mac, dst_mac, proto)
                name = "malicious_detection_time"
                #self.query_redis(name, detect_time[-6:], "lpush")
                return
            name = "genuine_detection_time"
            #self.query_redis(name, detect_time[-6:], "lpush")
        
        #if eth.ethertype != ether_types.ETH_TYPE_IP:
        #    self.logger.info("ARP found.")
        #    self.port_state[dpid].modify(port_no, port)
        #    return

        
        port.in_flows.append(new_flow)

        switch = self._get_switch(dpid)

        out_port_no = -1
        for p in switch.ports:
            if dst_mac in p.mac:
                out_port_no = p.port_no
                break

        value = ""
        for i in new_flow:
            value += str(i)
        #self.logger.info("value:%s", value)

        if out_port_no == -1:
            #self.logger.info("flood, no specific out port")
            name = port.name + "in"
            #self.logger.info("name:%s", name)
            self.query_redis(name, value, "add")

            for p in switch.ports:
                if p.__eq__(port):
                    continue
                else:
                    name = p.name + "out"
                    #self.logger.info("flood port: %s", p.name)
                    #self.logger.info("name: %s", name)
                    self.query_redis(name, value, "add")
            name = "flood_construction_time"
            t2 = datetime.datetime.now()
            construction_time = str(t2 - t1)
            #self.logger.info("COnstruction time :%s", construction_time)
            construction_time = construction_time[-6:]
            if detect_time:
                detect_time_float = float(detect_time[-6:])
                construction_time_float = float(construction_time)
            #self.query_redis(name, str(construction_time_float - detect_time_float), "lpush")
            return

        out_port = self._get_port(dpid, out_port_no)
        #self.logger.info("out port found: %s", out_port.name)
        name = out_port.name + "out"
        self.query_redis(name, value, "add")
        name = port.name + "in"
        self.query_redis(name, value, "add")
        t2 = datetime.datetime.now()
        #self.logger.info("t1:%s", str(t1))

        construction_time = str(t2 - t1)
        construction_time = construction_time[-6:]
        if detect_time:
            detect_time_float = float(detect_time)
            construction_time_float = float(construction_time)
        
        name = "construction_time"
        #self.query_redis(name, str(construction_time_float - detect_time_float), "lpush")
        return





    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def lldp_packet_in_handler(self, ev):
        if not self.link_discovery:
            return

        msg = ev.msg
        #print('************begin*************')
        #print(msg.data)
        #LOG.debug('*************end************')
        try:
            src_dpid, src_port_no = LLDPPacket.lldp_parse(msg.data)
        except LLDPPacket.LLDPUnknownFormat:
            # This handler can receive all the packets which can be
            # not-LLDP packet. Ignore it silently
            return

        dst_dpid = msg.datapath.id
        if msg.datapath.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            dst_port_no = msg.in_port
        elif msg.datapath.ofproto.OFP_VERSION >= ofproto_v1_2.OFP_VERSION:
            dst_port_no = msg.match['in_port']
        else:
            LOG.error('cannot accept LLDP. unsupported version. %x',
                      msg.datapath.ofproto.OFP_VERSION)

        src = self._get_port(src_dpid, src_port_no)

        if not src or src.dpid == dst_dpid:
            return
        try:
            self.ports.lldp_received(src)
        except KeyError:
            # There are races between EventOFPPacketIn and
            # EventDPPortAdd. So packet-in event can happend before
            # port add event. In that case key error can happend.
            # LOG.debug('lldp_received error', exc_info=True)
            pass

        dst = self._get_port(dst_dpid, dst_port_no)
        #LOG.debug('----------')
        #LOG.debug(CONF.ofp_listen_host)
        #LOG.debug(CONF.ofp_tcp_listen_port)
        #LOG.debug(type(dst.hw_addr))
        if not dst:
            return

        link = Link(src, dst)
        '''
        if CONF.environment == "underlay" and link not in self.links:
            self.logger.info("---------------------------")
            timestamp = str(datetime.datetime.now())
            timestamp = timestamp.replace(" ", "")
            t1 = datetime.datetime.now()
            check_res = self.underlay_security_check(src, dst, timestamp)
            t2 = datetime.datetime.now()
            detection_time = str(t2 - t1)
            if check_res == self.FAKE_LINK:
                name = "underlay_malicious_detection"
                #self.logger.info()
                #self.query_redis(name, detection_time[-6:], "lpush")
                return
            elif check_res == self.SECURE_LINK:
                name = "underlay_genuine_detection"
                #self.query_redis(name, detection_time[-6:], "lpush")
            else:
                return 
        '''

        #print('------------')
        #print(src.name)
        #print(dst.name)
        '''
        if link not in self.links:
        #    LOG.debug('begin checking')
            check_res = self.new_link_security_check(src, dst, msg)
            if check_res == self.FAKE_LINK:
                LOG.debug("New link %s:%s <-> %s:%s is a fake link", 
                          dpid_to_str(src.dpid), port_no_to_str(src.port_no),
                          dpid_to_str(dst.dpid), port_no_to_str(dst.port_no))
                return
            elif check_res == self.ENVIRONMENT_WRONG:
                LOG.error('Paradigm of environment is wrong(choose \'overlay\' or \'underlay\')')
                return
            elif check_res == self.OTHER_ERROR:
                LOG.error('Something wrong in link security check process')
                return
            elif check_res == self.CHECKING:
                LOG.debug('Link %s:%s <-> %s:%s is checked for the first time',
                          dpid_to_str(src.dpid), port_no_to_str(src.port_no),
                          dpid_to_str(dst.dpid) , port_no_to_str(dst.port_no))
                return
            else :
                LOG.debug('Link %s:%s <-> %s:%s is safe',
                          dpid_to_str(src.dpid), port_no_to_str(src.port_no),
                          dpid_to_str(dst.dpid), port_no_to_str(dst.port_no))
        '''

        old_peer = self.links.get_peer(src)
        # LOG.debug("Packet-In")
        # LOG.debug("  src=%s", src)
        # LOG.debug("  dst=%s", dst)
        # LOG.debug("  old_peer=%s", old_peer)
        if old_peer and old_peer != dst:
            old_link = Link(src, old_peer)
            del self.links[old_link]
            self.send_event_to_observers(event.EventLinkDelete(old_link))


        if link not in self.links:
            self.send_event_to_observers(event.EventLinkAdd(link))

            # remove hosts if it's not attached to edge port
            host_to_del = []
            for host in self.hosts.values():
                if not self._is_edge_port(host.port):
                    host_to_del.append(host.mac)

            for host_mac in host_to_del:
                del self.hosts[host_mac]

        if not self.links.update_link(src, dst):
            # reverse link is not detected yet.
            # So schedule the check early because it's very likely it's up
            self.ports.move_front(dst)
            self.lldp_event.set()
        if self.explicit_drop:
            self._drop_packet(msg)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def host_discovery_packet_in_handler(self, ev):
        msg = ev.msg
        eth, pkt_type, pkt_data = ethernet.ethernet.parser(msg.data)

        # ignore lldp and cfm packets
        if eth.ethertype in (ETH_TYPE_LLDP, ETH_TYPE_CFM):
            return

        datapath = msg.datapath
        dpid = datapath.id
        port_no = -1

        if msg.datapath.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            port_no = msg.in_port
        else:
            port_no = msg.match['in_port']

        port = self._get_port(dpid, port_no)

        # can't find this port(ex: logic port)
        if not port:
            return


        self.graph_construction(msg)
        # switch-to-switch port
        if not self._is_edge_port(port):
            self.logger.info("internal port")
            return

        host_mac = eth.src
        host = Host(host_mac, port)

        if host_mac not in self.hosts:
            self.hosts.add(host)
            ev = event.EventHostAdd(host)
            self.send_event_to_observers(ev)
        elif self.hosts[host_mac].port != port:
            # assumes the host is moved to another port
            ev = event.EventHostMove(src=self.hosts[host_mac], dst=host)
            self.hosts[host_mac] = host
            self.send_event_to_observers(ev)

        # arp packet, update ip address
        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arp_pkt, _, _ = pkt_type.parser(pkt_data)
            self.hosts.update_ip(host, ip_v4=arp_pkt.src_ip)

        # ipv4 packet, update ipv4 address
        elif eth.ethertype == ether_types.ETH_TYPE_IP:
            ipv4_pkt, _, _ = pkt_type.parser(pkt_data)
            self.hosts.update_ip(host, ip_v4=ipv4_pkt.src)

        # ipv6 packet, update ipv6 address
        elif eth.ethertype == ether_types.ETH_TYPE_IPV6:
            # TODO: need to handle NDP
            ipv6_pkt, _, _ = pkt_type.parser(pkt_data)
            self.hosts.update_ip(host, ip_v6=ipv6_pkt.src)
        
        #self.graph_construction(msg)

    def send_lldp_packet(self, port):
        try:
            port_data = self.ports.lldp_sent(port)
        except KeyError:
            # ports can be modified during our sleep in self.lldp_loop()
            # LOG.debug('send_lld error', exc_info=True)
            return
        if port_data.is_down:
            return

        dp = self.dps.get(port.dpid, None)
        if dp is None:
            # datapath was already deleted
            return

        # LOG.debug('lldp sent dpid=%s, port_no=%d', dp.id, port.port_no)
        # TODO:XXX
        if dp.ofproto.OFP_VERSION == ofproto_v1_0.OFP_VERSION:
            actions = [dp.ofproto_parser.OFPActionOutput(port.port_no)]
            dp.send_packet_out(actions=actions, data=port_data.lldp_data)
        elif dp.ofproto.OFP_VERSION >= ofproto_v1_2.OFP_VERSION:
            actions = [dp.ofproto_parser.OFPActionOutput(port.port_no)]
            out = dp.ofproto_parser.OFPPacketOut(
                datapath=dp, in_port=dp.ofproto.OFPP_CONTROLLER,
                buffer_id=dp.ofproto.OFP_NO_BUFFER, actions=actions,
                data=port_data.lldp_data)
            dp.send_msg(out)
        else:
            LOG.error('cannot send lldp packet. unsupported version. %x',
                      dp.ofproto.OFP_VERSION)

    def lldp_loop(self):
        while self.is_active:
            self.lldp_event.clear()

            now = time.time()
            timeout = None
            ports_now = []
            ports = []
            for (key, data) in self.ports.items():
                if data.timestamp is None:
                    ports_now.append(key)
                    continue

                expire = data.timestamp + self.LLDP_SEND_PERIOD_PER_PORT
                if expire <= now:
                    ports.append(key)
                    continue

                timeout = expire - now
                break

            for port in ports_now:
                self.send_lldp_packet(port)
            for port in ports:
                self.send_lldp_packet(port)
                hub.sleep(self.LLDP_SEND_GUARD)      # don't burst

            if timeout is not None and ports:
                timeout = 0     # We have already slept
            # LOG.debug('lldp sleep %s', timeout)
            self.lldp_event.wait(timeout=timeout)

    def link_loop(self):
        while self.is_active:
            self.link_event.clear()

            now = time.time()
            deleted = []
            for (link, timestamp) in self.links.items():
                # LOG.debug('%s timestamp %d (now %d)', link, timestamp, now)
                if timestamp + self.LINK_TIMEOUT < now:
                    src = link.src
                    if src in self.ports:
                        port_data = self.ports.get_port(src)
                        # LOG.debug('port_data %s', port_data)
                        if port_data.lldp_dropped() > self.LINK_LLDP_DROP:
                            deleted.append(link)

            for link in deleted:
                self.links.link_down(link)
                # LOG.debug('delete %s', link)
                self.send_event_to_observers(event.EventLinkDelete(link))

                dst = link.dst
                rev_link = Link(dst, link.src)
                if rev_link not in deleted:
                    # It is very likely that the reverse link is also
                    # disconnected. Check it early.
                    expire = now - self.LINK_TIMEOUT
                    self.links.rev_link_set_timestamp(rev_link, expire)
                    if dst in self.ports:
                        self.ports.move_front(dst)
                        self.lldp_event.set()

            self.link_event.wait(timeout=self.TIMEOUT_CHECK_PERIOD)

    @set_ev_cls(event.EventSwitchRequest)
    def switch_request_handler(self, req):
        # LOG.debug(req)
        dpid = req.dpid

        switches = []
        if dpid is None:
            # reply all list
            for dp in self.dps.values():
                switches.append(self._get_switch(dp.id))
        elif dpid in self.dps:
            switches.append(self._get_switch(dpid))

        rep = event.EventSwitchReply(req.src, switches)
        self.reply_to_request(req, rep)

    @set_ev_cls(event.EventLinkRequest)
    def link_request_handler(self, req):
        # LOG.debug(req)
        dpid = req.dpid

        if dpid is None:
            links = self.links
        else:
            links = [link for link in self.links if link.src.dpid == dpid]
        rep = event.EventLinkReply(req.src, dpid, links)
        self.reply_to_request(req, rep)

    @set_ev_cls(event.EventHostRequest)
    def host_request_handler(self, req):
        dpid = req.dpid
        hosts = []
        if dpid is None:
            for mac in self.hosts:
                hosts.append(self.hosts[mac])
        else:
            hosts = self.hosts.get_by_dpid(dpid)

        rep = event.EventHostReply(req.src, dpid, hosts)
        self.reply_to_request(req, rep)
