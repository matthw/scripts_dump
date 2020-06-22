# per source ip/destination pool rate limiting
# reference: https://devcentral.f5.com/questions/irule-for-rate-limiting-49300
#
# you need a data-group list of type "address" and name "http_rate_limiter_whitelist"

when RULE_INIT {
    set static::http_rate_limit_max_reqs 10
    set static::http_rate_limit_timeout 5
}

# low priority so we can catch pool selected in higher priorirty irule
when HTTP_REQUEST priority 800 {
    # get client ip addr, from x-fwd-for preferably
    if {[HTTP::header exists x-forwarded-for]} {
        set client_ip [getfield [lindex  [HTTP::header values x-forwarded-for]  0] "," 1]
    } else {
        set client_ip [getfield [IP::client_addr] "%" 1]
    }
    
    # if client ip doesnt match the whitelist; apply rate limiting
    if {![class match $client_ip equals http_rate_limiter_whitelist]} {

        set pool [LB::server pool]
        set table_name "${pool}_${client_ip}"
    
        #log local0. "pool: $pool"
    
        if {[set req_count [table incr -subtable rate_limit -mustexist "$table_name" ]] ne ""} {
            if {$req_count > $static::http_rate_limit_max_reqs} {
                HTTP::respond 429 content { 
          You are too fast for me...

                  ______
                 /|_||_\`.__
   vrrooooom !  (   _    _ _\ 
            'o. =`-(_)--(_)-' 
                } "Content-Type" "text/plain"
                return
            }
        }
        else {
            table set -subtable rate_limit "$table_name" 1 indefinite $static::http_rate_limit_timeout
        }
    }
}
