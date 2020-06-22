#!/bin/bash
# matthieu walter - 2017
 
#
# list virtual servers listening on port 443
#
list_https_vs() {
        tmsh list /ltm virtual "/Partition/*" \
        | awk '
                /^ltm virtual/ { vs=$3 }
                /destination .*:(https|443)$/ { print vs }
        '
}
 
#
# return the client-ssl profile associated with the virtual server ($1)
#
list_client_ssl_profile() {
        tmsh show ltm virtual "$1" profiles | grep ClientSSL | awk '{ print $(NF) }'
}
 
#
# return common name and SAN from the certificate associated with
# the client-ssl profile ($1)
#
show_cert_from_profile() {
        tmsh list ltm profile client-ssl "$1" | awk '$1 == "cert" { print $2 }' | sort -u \
        | while read cert; do
                tmsh list sys crypto cert ${cert} \
                | grep -E "^ *(common-name|subject-alternative-name) " \
                | sed -e 's/^ *[^ ]* //' -e 's/, /,/g' \
                | tr ',' '\n' | sed 's/^DNS://' \
                | sort -u
        done
}
 
list_https_vs | while read vs; do
        echo "VS: $vs"
        list_client_ssl_profile "${vs}" | while read ssl_prof; do
                echo "   client_ssl_profile: ${ssl_prof}"
                show_cert_from_profile "${ssl_prof}" | while read host; do
                        echo "   +--  ${host}"
                done
        done
        echo ""
done
