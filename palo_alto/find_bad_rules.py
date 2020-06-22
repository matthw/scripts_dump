#!/usr/bin/python
#
# mw 2020
# flag all rules with no "directly connected" object
# run first with --dump to dump all rules to a json file
#
# 1. pip install pan-python
# 2. create an api user on the PA
# 3. generate api key
#    panxapi.py -h 10.10.10.10 -l username:password -k
#    keygen: success
#    API key:  "AABCD="


from collections import OrderedDict
from mypa import *
import sys
import json
import ipaddress


PANDEV = "panorama.host.local"
PANKEY = "your-api-key"

####
#### Define ranges which belongs to the firewall we want to process
#### and also the device group


# TEST
device_group = "DEVICE_GROUP"

# interfaces list
_SRC = [
    "10.18.23.3/24",
    "192.168.1.3/22"
    ]


SRC = []

for s in _SRC:
    SRC.append(ipaddress.ip_network(unicode(s), strict=False))



def good_addr(src):
    """ returns true if an address or a range is part (subnet/supernet)
    of the firewall we process -> only works for directly connected routes.
    """
    #s = ".".join(src.split(".")[:2])

    # iprange
    if type(src) is list:
        pass

    # normal range
    else:
        src = [src]



    # iterates over source
    for s in src:
        for check in SRC:
            if s.subnet_of(check) or s.supernet_of(check):
                return True

    return False



pa = PA(PANDEV, PANKEY, root="")


#
# LOAD ALL SHARED ADDRESS and convert to CIDR in case of ip-netmask / ip-range
#
_addr = pa.get("/config/shared/address")["address"]["entry"]
address = {}
for a in _addr:
    if a.has_key("ip-netmask"):
        ip = a["ip-netmask"]["$"]
        if "/" not in ip:
            ip = ip + "/32"

        ip = ipaddress.ip_network(unicode(ip), strict=False)

        address[a["@name"]] = ip

    elif a.has_key("fqdn"):
        # this needs to be handled...
        address[a["@name"]] = a["fqdn"]["$"]

    elif a.has_key("ip-range"):
        rg = a["ip-range"]["$"]
        ip1, ip2 = rg.split("-")
        ip1 = ipaddress.ip_address(unicode(ip1))
        ip2 = ipaddress.ip_address(unicode(ip2))
        address[a["@name"]] = list(ipaddress.summarize_address_range(ip1, ip2))
    else:
        raise Exception

print "# loaded %d addresses"%len(address)

#
# LOAD ALL GROUPS
#
_grp = pa.get("/config/shared/address-group")["address-group"]["entry"]
addr_group = {}

count = 0
# group in groups...
# make 3 pass to be sure we handle groups in groups (3 seems to be enough)
# could have been recursive...
while len(_grp) and count < 3:
    count += 1
    #print "loop %d"%count

    rejects = []

    for g in _grp:
        addr_group[g["@name"]] = []


        if not g.has_key("static"):
            addr_group[g["@name"]] = []
            continue

        if type(g["static"]["member"]) is OrderedDict:
            g["static"]["member"] = [g["static"]["member"]]
        
        for a in g["static"]["member"]:
            name = a["$"]

            # addr
            if address.has_key(name):
                addr_group[g["@name"]].append(address[name])
            # addr group
            elif addr_group.has_key(name):
                addr_group[g["@name"]] += addr_group[name]

            # not found
            else:
                #del addr_group[g["@name"]]
                rejects.append(g)
    _grp = rejects
        

print "# loaded %d address-groups"%len(addr_group)


#
# LOAD ALL RULES FROM DEVICE GROUP
# it takes time to load everything so we cheat:
# 1 pass to save the result as json
# other pass will just load the json from file to speed up the process
#

print "using device group: %s"%device_group
print "using these ranges: %r"%_SRC


if len(sys.argv) == 2 and sys.argv[1] == "--dump":
    print "# dumping rules to rules.%s ..."%device_group
    with open("rules.%s"%device_group, "w") as fp:
        json.dump(pa.get("/config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='%s']/post-rulebase"%device_group),
                    fp,
                    sort_keys=True, indent=4, separators=(',', ': '))
    sys.exit(0)


_rules = json.load(open("rules.%s"%device_group, "r"))["post-rulebase"]["security"]["rules"]["entry"]
rules = {}

for r in _rules:
    rules[r["@name"]] = {
        "uuid": r["@uuid"],
        # source/dest addr
        "source": r["source"]["member"],
        "destination": r["destination"]["member"],
        # source/dest zone
        "from": r["from"],
        "to": r["to"],
        }

    #print rules[r["@name"]]["source"]

    if r.has_key("disabled"):
        rules[r["@name"]]["disabled"] = r["disabled"]["$"]
    else:
        rules[r["@name"]]["disabled"] = "no"

del _rules
print "# loaded %d rules (%s)"%(len(rules), device_group)



#
# LOOP THE RULES
# check if their source/destination belongs to the firewall
#

fp_rules = open("%s.rules_to_delete"%device_group, "w")


for r in rules:
    rule = rules[r]
    print "# -----"
    print "# '%s' / %s"%(r, rule["uuid"])

    if type(rule["source"]) is dict:
        rule["source"] = [rule["source"]]

    if type(rule["destination"]) is dict:
        rule["destination"] = [rule["destination"]]

    src = []
    dest = []

    # convert source objets to list of CIDR
    for x in rule["source"]:
        if address.has_key(x["$"]):
            if type(address[x["$"]]) is list:
                 src += address[x["$"]]
            else:
                src.append(address[x["$"]])
        elif addr_group.has_key(x["$"]):
            src += addr_group[x["$"]]
        else:
            print "# ERROR : object %s not found"%x["$"]

    # the same for destination
    for x in rule["destination"]:
        if address.has_key(x["$"]):
            if type(address[x["$"]]) is list:
                dest += address[x["$"]]
            else:
                dest.append(address[x["$"]])
        elif addr_group.has_key(x["$"]):
            dest += addr_group[x["$"]]
        else:
            print "# ERROR : object %s not found"%x["$"]

    print "# src: %r"%src
    print "# dst: %r"%dest


    # count source objects matching the fw
    count_src = 0
    for s in src:
        if good_addr(s):
            count_src += 1

    # same for dest
    count_dst = 0
    for d in dest:
        if good_addr(d):
            count_dst += 1

    # disable rule, make it but do nothing
    if rule["disabled"] == "yes":
        print "# DISABLED"
        print "# action = DELETE"
        #XXX
        fp_rules.write("%s\n"%r)
        continue

    # if all source are in correct "zone"
    #if count == len(src):
    if count_src or not len(src):
        print "# action = KEEP_SOURCE"

    # keep when destination is our FW or any
    elif count_dst or not len(dest):
        print "# action = KEEP_DESTINATION"

    else:
        print "# action = DELETE"
        print 'delete device-group %s post-rulebase security rules "%s"'%(device_group, r)
        fp_rules.write("%s\n"%r)

    if count_src and count_src < len(src):
        print "# MIXED UP, mixed source network: '%s'"%r

fp_rules.close()
