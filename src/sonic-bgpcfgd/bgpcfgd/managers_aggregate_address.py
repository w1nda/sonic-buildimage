from swsscommon import swsscommon

from .log import log_info
from .manager import Manager
from .managers_bbr import BGP_BBR_TABLE_NAME, BGP_BBR_STATUS_KEY, BGP_BBR_STATUS_ENABLED, BGP_BBR_STATUS_DISABLED

CONFIG_DB_NAME = "CONFIG_DB"
BGP_AGGREGATE_ADDRESS_TABLE_NAME = "BGP_AGGREGATE_ADDRESS"
BBR_REQUIRED_KEY = "bbr_required"
AS_SET_KEY = "as-set"
SUMMARY_ONLY_KEY = "summary-only"
AGGREGATE_ADDRESS_PREFIX_LIST_KEY = "aggregate-address-prefix-list"
CONTRIBUTING_ADDRESS_PREFIX_LIST_KEY = "contributing-address-prefix-list"
COMMON_TRUE_STRING = "true"
COMMON_FALSE_STRING = "false"
ADDRESS_STATE_KEY = "state"
ADDRESS_ACTIVE_STATE = "active"
ADDRESS_INACTIVE_STATE = "inactive"


class AggregateAddressMgr(Manager):
    """ This class is to subscribe BGP_AGGREGATE_ADDRESS in CONFIG_DB """

    def __init__(self, common_objs, db, table):
        """
        Initialize the object
        :param common_objs: common object dictionary
        :param db: name of the db
        :param table: name of the table in the db
        """
        super(AggregateAddressMgr, self).__init__(
            common_objs,
            [],
            db,
            table,
        )
        self.directory.subscribe([(CONFIG_DB_NAME, BGP_BBR_TABLE_NAME, BGP_BBR_STATUS_KEY)], self.on_bbr_change)
        self.state_db_conn = common_objs['state_db_conn']
        self.address_table = swsscommon.Table(self.state_db_conn, BGP_AGGREGATE_ADDRESS_TABLE_NAME)
        self.remove_all_state_of_address()

    def on_bbr_change(self):
        bbr_status = self.directory.get(CONFIG_DB_NAME, BGP_BBR_TABLE_NAME, BGP_BBR_STATUS_KEY)
        addresses = self.get_addresses_from_state_db(bbr_required_only=True)
        if bbr_status == BGP_BBR_STATUS_ENABLED:
            log_info("AggregateAddressMgr::BBR state changed to %s with bbr_required addresses " % bbr_status, addresses)
            for address in addresses:
                if self.address_set_handler(address[0], address[1]):
                    self.set_state_db(address, True, ADDRESS_ACTIVE_STATE)
        elif bbr_status == BGP_BBR_STATUS_DISABLED:
            log_info("AggregateAddressMgr::BBR state changed to %s with bbr_required addresses " % bbr_status, addresses)
            for address in addresses:
                if self.address_del_handler(address[0], address[1]):
                    self.set_state_db(address, True, ADDRESS_INACTIVE_STATE)
        else:
            log_info("AggregateAddressMgr::BBR state changed to unknown with bbr_required addresses " % bbr_status, addresses)

    def set_handler(self, key, data):
        bbr_status = self.directory.get(CONFIG_DB_NAME, BGP_BBR_TABLE_NAME, BGP_BBR_STATUS_KEY)
        if bbr_status not in (BGP_BBR_STATUS_ENABLED, BGP_BBR_STATUS_DISABLED):
            log_info("AggregateAddressMgr::BBR state is unknown. Skip the address")
            self.set_state_db(key, data, ADDRESS_INACTIVE_STATE)
        elif bbr_status == BGP_BBR_STATUS_DISABLED and data[BBR_REQUIRED_KEY] == COMMON_TRUE_STRING:
            log_info("AggregateAddressMgr::BBR is disabled and bbr-required is set to true. Skip the address")
            self.set_state_db(key, data, ADDRESS_INACTIVE_STATE)
        else:
            if self.address_set_handler(data):
                self.set_state_db(key, data, ADDRESS_ACTIVE_STATE)
            else:
                log_info("AggregateAddressMgr::set address %s failed" % key)
                self.set_state_db(key, data, ADDRESS_INACTIVE_STATE)
        return True

    def address_set_handler(self, key, data):
        bgp_asn = self.directory.get_slot(CONFIG_DB_NAME, swsscommon.CFG_DEVICE_METADATA_TABLE_NAME)["localhost"]["bgp_asn"]
        cmd_list = []
        cmd_list.append("router bgp %s" % bgp_asn)

        if '.' in key:
            cmd_list.append("address-family ipv4")
        else:
            cmd_list.append("address-family ipv6")

        agg_addr_cmd = "aggregate-address %s" % key
        if SUMMARY_ONLY_KEY in data and data[SUMMARY_ONLY_KEY] == COMMON_TRUE_STRING:
            agg_addr_cmd += " %s" % SUMMARY_ONLY_KEY
        if AS_SET_KEY in data and data[AS_SET_KEY] == COMMON_TRUE_STRING:
            agg_addr_cmd += " %s" % AS_SET_KEY

        log_info("AggregateAddressMgr::cmd_list: %s" % cmd_list)
        self.cfg_mgr.push_list(cmd_list)
        return True

    def del_handler(self, key):
        if self.address_del_handler(key):
            log_info("AggregateAddressMgr::delete address %s success" % key)
            self.del_state_db(key)
        return True

    def address_del_handler(self, key):
        self.del_state_db(key)
        bgp_asn = self.directory.get_slot("CONFIG_DB", swsscommon.CFG_DEVICE_METADATA_TABLE_NAME)["localhost"]["bgp_asn"]
        cmd_list = []
        cmd_list.append("router bgp %s" % bgp_asn)

        if '.' in key:
            cmd_list.append("address-family ipv4")
        else:
            cmd_list.append("address-family ipv6")

        cmd_list.append("no aggregate-address %s" % key)
        log_info("AggregateAddressMgr::cmd_list: %s" % cmd_list)
        self.cfg_mgr.push_list(cmd_list)
        return True

    def get_addresses_from_state_db(self, bbr_required_only=False):
        addresses = []
        for address in self.address_table.getKeys():
            bbr_required = self.address_table.hget(address, BBR_REQUIRED_KEY)
            if not bbr_required_only or bbr_required == COMMON_TRUE_STRING:
                data = {}
                _as_set = self.address_table.hget(address, AS_SET_KEY)
                if _as_set:
                    data[AS_SET_KEY] = _as_set
                _summary_only = self.address_table.hget(address, SUMMARY_ONLY_KEY)
                if _summary_only:
                    data[SUMMARY_ONLY_KEY] = _summary_only
                addresses.append((address, data))
        return addresses

    def remove_all_state_of_address(self):
        for address in self.address_table.getKeys():
            self.address_table.delete(address)
        log_info("AggregateAddressMgr::All the state of aggregate address is removed")
        return True

    def set_state_db(self, key, data, address_state):
        self.address_table.hset(key, BBR_REQUIRED_KEY, data[BBR_REQUIRED_KEY])
        self.address_table.hset(key, ADDRESS_STATE_KEY, address_state)
        log_info("AggregateAddressMgr::State of aggregate address %s is set with bbr_required %s and state %s " % (key, data[BBR_REQUIRED_KEY], address_state))

    def del_state_db(self, key):
        self.address_table.delete(key)
        log_info("AggregateAddressMgr::State of aggregate address %s is removed" % key)
