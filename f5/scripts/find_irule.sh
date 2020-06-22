#!/bin/sh
# 2017 matthieu walter 
 
#
# OUTPUT FORMAT:
# vs | irule
list_irules_by_vs() {
        tmsh list ltm virtual "/*/*" rules \
        | awk '
        BEGIN { in_rule = 0 }
        #
        # beginning of virtual server
        /^ltm virtual / {
                vs=$3
                next
        }
        #
        # beginning of rule list
        /^ .*rules {/ {
                in_rule = 1
                next
        }
        #
        # end of section
        $1 == "}" {
                # end of irule section
                if (in_rule) {
                        in_rule = 0
                }
                next
        }
        #
        # for any other line, check that we are in
        # the irule section
        {
                if (in_rule) {
                        # irules in /Common partition are not
                        # prefixed with partition name
                        if (index($1, "/") != 1) {
                                printf("%s|/Common/%s\n", vs, $1)
                        } else {
                                printf("%s|%s\n", vs, $1)
                        }
                }
        }
        '
}
 
if [ -z "$1" ]; then
        echo "usage: $0 <irule name>"
        echo ""
        echo "Note:"
        echo " - irule name can be a glob expression like '*rule*'"
        echo " - it's case insensitive"
        exit 1
fi
 
IFS="|"
list_irules_by_vs | while read vs rule; do
        # case insensitive match
        shopt -s nocasematch
        if [[ $rule = $1 ]]; then
                echo "$rule  -> $vs"
        fi
done | sort -k1,3
