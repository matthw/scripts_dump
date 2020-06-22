# unknown author
# 20181018 matth -> fixed an issue where Location header was rewritten
#                   while redirecting to a different domain

when RULE_INIT {
    set static::debug 0
}

when HTTP_REQUEST priority 600 {
    #get variables in lowercase
    set orig_host [string tolower [getfield [HTTP::host] : 1]]
    set orig_uri [string tolower [HTTP::uri]]

    set clientside ""
	set serverside ""
	set newpool ""
	set ppass ""
	set match 0

    set className "ProxyPass_$orig_host"

    if {! [class exists $className] } {
        reject
	    event disable all
	    log local0. "No data-group found for $orig_host"
        return
    }

    set ppass [class match -element "$orig_host$orig_uri" starts_with $className]
	if {$ppass eq ""} {
		# Did not find with hostname, look for just path
		set ppass [class match -element "$orig_uri" starts_with $className]
	}
	if {$ppass eq ""} {
	    reject
	    event disable all
	    log local0. "No entry found for $orig_host$orig_uri"
		# No entry found
		return
	}

	#get variables case sensitive
	set orig_host [getfield [HTTP::host] : 1]
    set orig_uri [HTTP::uri]

	set match 1

	# Store each entry in the data group line into a local variable
	set clientside [getfield $ppass " " 1]
	set serverside [string trimleft [getfield $ppass " " 2 ] "{" ]
	set newpool [string trimright [getfield $ppass " " 3 ] "}" ]

	if { $serverside equals "!" } {
	    reject
	    event disable all
	    return
	}

	if {$clientside starts_with "/"} {
		# No virtual hostname specified, so use the Host header instead
		set host_clientside $orig_host
		set path_clientside $clientside
	} else {
		# Virtual host specified in entry, split the host and path
		set host_clientside [getfield $clientside "/" 1]
		set path_clientside [substr $clientside [string length $host_clientside]]
	}
	# At this point $host_clientside is the client hostname, and $path_clientside
	# is the client-side path as specified in the data group

	set host_serverside [getfield $serverside "/" 1]
	set path_serverside [substr $serverside [string length $host_serverside]]
	if {$host_serverside eq ""} {
		set host_serverside $host_clientside
	}
	# At this point $host_serverside is the server hostname, and $path_serverside
	# is the server-side path as specified in the data group

	if {$newpool ne ""} {
	    pool $newpool
	}
}

when HTTP_REQUEST_RELEASE {
    if { $match eq 0 } {
        return
    }
    if { $static::debug == 1 } {
        log local0. "Old uri: [HTTP::uri]"
    }
    HTTP::uri $path_serverside[substr $orig_uri [string length $path_clientside]]
    if { $static::debug == 1 } {
        log local0. "New uri: [HTTP::uri]"
    }
	# Rewrite the Host header
	HTTP::header replace Host $host_serverside
	# Now alter the Referer header if necessary
	#if { [HTTP::header exists "Referer"] } {
	#	 set protocol [URI::protocol [HTTP::header Referer]]
	#	 if {$protocol ne ""} {
	#		  set client_path [findstr [HTTP::header "Referer"] $host_clientside [string length $host_clientside]]
	#		  if {$client_path starts_with $path_clientside} {
	#				HTTP::header replace "Referer" "$protocol://$host_serverside$path_serverside[substr $client_path [string length $path_clientside]]"
	#		  }
	#	 }
	#}
}

when HTTP_RESPONSE {
    if { $match eq 0 } {
        return
    }
    foreach header {"Location" "Content-Location" "URI"} {
		set protocol [URI::protocol [HTTP::header $header]]
		if {$protocol ne ""} {
		    # maz 20181018 - no location header rewrite if redirection domain is different
		    set redirect_host  [string tolower [getfield [URI::host [HTTP::header $header]] : 1]]
		    #log local0. "redirection from $host to $redirect_host"
		    if {$redirect_host ne $orig_host} {
		        return
		    }
			set server_path [findstr [HTTP::header $header] $host_serverside [string length $host_serverside]]
			if {$server_path starts_with $path_serverside} {
				HTTP::header replace $header $protocol://$host_clientside$path_clientside[substr $server_path [string length $path_serverside]]
			}
		}
	}
}
