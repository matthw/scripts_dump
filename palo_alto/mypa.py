#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
#
# matthieu walter 2018

import sys
import logging
import json
import pan.xapi
from collections import OrderedDict
from xml.etree.ElementTree import fromstring
from xmljson import badgerfish as bf

options = {
    'print_xml': False,
    'print_python': True,
    'print_text': False,
    'print_json': True,
    'print_result': True
}

def json_pp(string):
    print json.dumps(string,  sort_keys=True, indent=4, separators=(',', ': '))

def clres(result):
    return result["response"]["result"]


class PA:
    def __init__(self, addr, apikey, root="/config/devices/entry[@name='localhost.localdomain']/vsys/entry[@name='vsys1']"):
        try:
            self.xapi = pan.xapi.PanXapi(hostname=addr, api_key=apikey)
        except pan.xapi.PanXapiError as msg:
            print('error: %s'%msg)
            sys.exit(1)

        self.root = root

    def resolve(self, obj):
        ''' this is bad
        '''
        res = self.get_address(obj)
        if len(res):
            return res["entry"]["ip-netmask"]['$']
        else:
            # if it's a group, recursively resolve
            res = self.get_address_group(obj)
            if len(res):
                resolved = []
                if type(res["entry"]["static"]["member"]) is OrderedDict:
                    res["entry"]["static"]["member"] = [res["entry"]["static"]["member"]]
                for h in res["entry"]["static"]["member"]:
                    resolved += [self.resolve(h['$'])]
                return resolved
               

        return []

    def get(self, xpath):
        self.xapi.get(self.root + xpath)
        xml = fromstring(self.xapi.xml_root().encode("utf-8"))
        return clres(bf.data(xml))

    
    def get_address(self, address=None):
        """ return an address object  (or all)
        """
        return self.__get_addr_grp('address', address)
    
    def get_address_group(self, group=None):
        """ return an address-group object (or all)
        """
        return self.__get_addr_grp('address-group', group)


    def __get_addr_grp(self, objtype, address=None):
        """ return an address or address group
        """
        if address is not None:
            return self.get("/%s/entry[@name='%s']"%(objtype, address))
        else:
            return self.get("/%s/entry"%objtype)


    def search_address(self, address):
        """ search an address
        """
        search = "(contains(translate(@name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'),'%s' ))"\
                 "or (contains(translate(ip-netmask, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'),'%s' ))"\
                 "or (contains(translate(ip-range, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'),'%s' ))"\
                 "or (contains(translate(fqdn, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'),'%s' ))"\
                 "or (contains(translate(description, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'),'%s' ))"\
                 "or (contains(translate(tag, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'),'%s' ))" \
                 % (address, address, address, address, address, address)

        return self.get("/address/entry[%s]"%(search))


    def search_rule(self, rule):
        # /rulebase/security/rules/entry
        search = "((contains(translate(@name, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'),'%s' ))"\
                 "or (contains(translate(description, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'),'%s' ))"\
                 "or (contains(translate(tag, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'),'%s' ))"\
                 "or (contains(translate(from, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'),'%s' ))"\
                 "or (contains(translate(to, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'),'%s' ))"\
                 "or (contains(translate(source, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'),'%s' ))"\
                 "or (contains(translate(destination, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'),'%s' ))"\
                 "or (contains(translate(source-user, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'),'%s' ))"\
                 "or (contains(translate(application, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'),'%s' ))"\
                 "or (contains(translate(service, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'),'%s' ))"\
                 "or (contains(translate(category, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz'),'%s' )))"\
                 % (rule, rule, rule, rule, rule, rule, rule, rule, rule, rule, rule)

        return self.get("/rulebase/security/rules/entry[%s]"%(search))


    def traffic_log(self, nlogs=None, filter=None):
        ''' go through traffic log
        '''
        # needs extra_qs='dir=backward' // bug PAN-74932
        self.xapi.log(log_type='traffic', nlogs=nlogs, filter=filter, extra_qs='dir=backward')
        return bf.data(fromstring(pa.xapi.xml_root().encode('utf-8')))
        

