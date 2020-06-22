#
# F5 implementation of netscaler "callout" using sideband connection for Citrix Sharefile
# if the callout if done via https, we use an extra virtual server to offload ssl
#
# 2017 Matthieu Walter 
# with some help:
# https://devcentral.f5.com/articles/conditioning-irule-logic-on-external-information-01-httpretry
# https://devcentral.f5.com/codeshare/sideband-connection-http-example

when RULE_INIT {
    # Log debug messages to /var/log/ltm? 1=yes, 0=no
    set static::sb_debug 0

    # Number of times to try getting the sideband server response HTTP headers
    set static::retries 10

    # vhost to use when calling the backend (http host: header)
    set static::vhost "sharefile.xyz.com"

    # vserver to call (used to handle SSL...)
    set static::vserver "ssl_offloading_virtual_server"

    # ASM self ips
    set static::asm_self_ips {"10.1.1.2" "10.1.1.2"}
}


proc get_http_status { callout_url } {

    set conn [connect -timeout 1000 -idle 30 -status conn_status $static::vserver]
    #if {$static::sb_debug} { log local0. "get_http_status Connect returns: <$conn> and conn status: <$conn_status>" }

    if {$conn eq ""} {
        if {$static::sb_debug} { log local0. "get_http_status Connection could not be established " }
        return
    }

    # get connection infos
    set conn_info [connect info -idle -status $conn]
    #if {$static::sb_debug} { log local0. "get_http_status Connect info: <$conn_info>" }

    # set payload
    set payload "GET $callout_url HTTP/1.0\r\nHost: $static::vhost\r\n\r\n"
    set send_info [send -timeout 3000 -status send_status $conn $payload]

    set code 0
    set start [clock clicks -milliseconds]
    for {set i 0} {$i <= $static::retries} {incr i}{

        # See what data we have received so far on the connection with a 10ms timeout
        set recv_data [recv -peek -status peek_status -timeout 10 $conn]
        #if {$static::sb_debug} { log local0. "get_http_status Peek ([string length $recv_data]): $recv_data" }

        # Check if we have received the response headers (terminated by two CRLFs)
        if {[string match "HTTP/*\r\n\r\n*" $recv_data]}{
            regexp -line {^HTTP/[12]\.[0-9] ([0-9][0-9][0-9]) } $recv_data matched code

            if {$static::sb_debug} { log local0. "get_http_status Found the end of the HTTP headers" }
            break
        }
    }

    # Get the response
    #if {$static::sb_debug} { log local0. "get_http_status Recv data ([string length $recv_data] bytes) in [expr {[clock clicks -milliseconds] - $start}] ms:\
    #    <$recv_data>, peek status: <$peek_status>" }
    if {$static::sb_debug} {
        log local0. "get_http_status Recv data ([string length $recv_data] bytes) in [expr {[clock clicks -milliseconds] - $start}] ms - peek status: <$peek_status>"
    }

    # Debug: log the payload in hex to show non-printable characters like CRLFs
    #binary scan $recv_data H* recv_data_hex
    #if {$static::sb_debug} { log local0. "log_prefix \$recv_data_hex: $recv_data_hex" }

    close $conn
    if {$static::sb_debug} {
        #log local0. "get_http_status Closed, conn info: <[connect info -status $conn]>"
        log local0. "get_http_status Returning code $code"
    }

    return $code
}

when HTTP_REQUEST {
    #log local0. "Sharefile request from: [IP::client_addr]:[TCP::client_port]"

    # persistence based on tokenid= value from the URL
    set tokenid_session [URI::query [HTTP::uri] "uploadid"]
    if { $tokenid_session != "" } {
        persist uie $tokenid_session
    }

    ##Content switching
    if { !([HTTP::uri]  contains "/cifs/") and !([HTTP::uri] contains "/sp/") } {
        #Sharefile data request
        set req_type "data"
        set dest_pool pool_sharefile
	} elseif { ([HTTP::uri] contains "/cifs/") or  ([HTTP::uri] contains "/sp/") } {
        #Sharefile connector request
        set req_type "connector"
        set dest_pool pool_sharefile
	}


    # exclude ASM nonfloating self IP 
    if {[lsearch -exact $static::asm_self_ips [lindex [split [IP::client_addr] "%"] 0]] < 0} {
        log local0. "Sharefile: ($req_type) [HTTP::uri]"

        ##check valid URI signatures
        if { !([HTTP::uri] contains "/crossdomain.xml") and !([HTTP::uri] contains "/validate.ashx?requri") } {
            # extract what should be base64 encoded
            regexp {(.*?)(&h=.*)?$} [HTTP::uri] matched url
            set b64url [b64encode $url]

            # build callout url
            if { ([HTTP::uri] contains "&h=")  } {
                set value_of_h [URI::query [HTTP::uri] "h"]
                set callout "/validate.ashx?RequestURI=$b64url&h=$value_of_h"
            } else {
                # do something sf_callout_y
                set callout "/validate.ashx?RequestURI=$b64url&h="
            }

            # call url and check response code
            log local0. "Sharefile: Calling $callout"
            set response [call get_http_status $callout]

            if {$response != 200} {
                log local0. "Sharefile: Invalid callout response (http: $response) -> rejecting"
                reject
                return
            }
            log local0. "Sharefile: correct callout response (http: $response) -> allowed"
        }
    }
    pool $dest_pool
}
