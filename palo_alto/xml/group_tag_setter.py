#!/usr/bin/python
# 
# set group-tag to leverage on the panos9.0 feature "view rulebase as groups"
# use first available tag, if any
#
# 1/ save and export condig snapshot with only the one interesting device group
# 2/ edit xml (with the script)
# 3/ upload back and load config partial
#   load config partial from-xpath devices/entry[@name='localhost.localdomain']/device-group/entry[@name='INPUT-DEVICE-GROUP']/post-rulebase/security to-xpath /config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='DEVICE_GROUP_TO_REPLACE']/post-rulebase/security from uploaded_config_snapshot_name.xml
#
# matthieu walter 2020

from xml.etree import ElementTree
import sys


# if possible do not use one of these tags as group-tag
SKIP_TAG_IF_POSSIBLE = ["IMPORT", "robot:delete"]


def is_disabled(rule):
    ''' check if a rule is disabled
    '''
    for child in rule.getchildren():
        if child.tag == 'disabled':
            if child.text == 'yes':
                return True

    return False


def has_group_tag(rule):
    ''' check if it already has a group-tag
    '''
    for child in rule.getchildren():
        if child.tag == 'group-tag':
            return True

    return False


def get_tags(rule):
    ''' return the tags of the rule
    '''
    tag_list = []

    # find existing tags if any
    for child in rule.getchildren():
        if child.tag == 'tag':
            for t in child.getchildren():
                if t.tag == 'member':
                    tag_list.append(t.text)

    return tag_list


def set_group_tag(rule, new_tag):
    ''' set group-tag
    '''
    tag_child = None
    # find existing tags if any
    for child in rule.getchildren():
        if child.tag == 'group-tag':
            #print "found tag"
            tag_child = child
            break


    # if the rule had no tags, create a <group-tag></group-tag> node
    if tag_child is None:
        #print "creating new tag"
        tag_child = ElementTree.SubElement(rule, 'group-tag')

    # finally: add tag
    tag_child.text = new_tag
    return True



# load xml in memory and find root node
document = ElementTree.parse(sys.argv[1])
config = document.getroot()


# iterates through all the post-rules
# there should only be one device group in the file...
count = 0
for rule in config.findall('devices/entry/device-group/entry/post-rulebase/security/rules/entry'):
    count += 1
    group_tag = None
    rule_name = rule.attrib['name']

    # skip if already has a group-tag
    if has_group_tag(rule):
        print "rule: '%s'    --  SKIPPING"%rule_name
        continue

    # get tags
    tags = get_tags(rule)

    # no tag -> skip
    if not len(tags):
        print "rule: '%s'    --  SKIPPING"%rule_name
        continue

    # only one tag, pick it
    elif len(tags) == 1:
        group_tag = tags[0]
    
    # else, try to find one which is not in the
    # unpreferred tags list
    else:
        for t in tags:
            if t not in SKIP_TAG_IF_POSSIBLE:
                group_tag = t
                break

    # all unpreferred tags
    if group_tag is None:
        # here we should pick one
        raise Exception

    print "rule: '%s'    --  group_tag: %s"%(rule_name, group_tag)
    set_group_tag(rule, group_tag)



# save result to output.xml
document.write("output.xml")

