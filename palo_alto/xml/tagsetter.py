#!/usr/bin/python
# 1/ save and export condig snapshot with only the one interesting device group
# 2/ edit xml (with the script)
# 3/ upload back and load config partial
#   load config partial from-xpath devices/entry[@name='localhost.localdomain']/device-group/entry[@name='SRC-DG']/post-rulebase/security to-xpath /config/devices/entry[@name='localhost.localdomain']/device-group/entry[@name='DST-DG']/post-rulebase/security from merge.xml
# matth 2020

from xml.etree import ElementTree
import sys





def is_disabled(node):
    ''' check if a rule is disabled
    '''
    for child in node.getchildren():
        if child.tag == 'disabled':
            if child.text == 'yes':
                return True

    return False


def add_tag(node, new_tag):
    ''' add a tag to a rule, only if the tag is not there yet
    '''
    tag_child = None

    # find existing tags if any
    for child in node.getchildren():
        if child.tag == 'tag':
            print "found tag"
            tag_child = child
            break

    # if there's existing tags:
    # check if the tag we want to add already exists
    if tag_child is not None:
        for t in tag_child.getchildren():
            if t.tag == 'member':
                if t.text == new_tag:
                    print "tag already exists"
                    return False


    # if the rule had no tags, create a <tag></tag> node
    else:
        print "creating new tag"
        tag_child = ElementTree.SubElement(node, 'tag')

    
    # finally: add tag
    memb = ElementTree.SubElement(tag_child, 'member')
    memb.text = new_tag
    return True

                    


# load xml in memory and find root node
document = ElementTree.parse(sys.argv[1])
config = document.getroot()


# iterates through all the post-rules
# there should only be one device group in the file...
for rule in config.findall('devices/entry/device-group/entry/post-rulebase/security/rules/entry'):
    rule_name = rule.attrib['name']

    if is_disabled(rule):
        print "DISABLED RULE: %s"%rule_name

        add_tag(rule, "robot:delete")

# save result to output.xml
document.write("output.xml")

