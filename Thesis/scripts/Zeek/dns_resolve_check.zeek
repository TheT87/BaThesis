@load site/packages/zeek-agent-v2
@load site/packages/zeek-agent-v2/framework/main
@load site/packages/zeek-agent-v2/table
@load site/zeek-agent-v2
@load site/zeek-agent-v2/framework
@load site/zeek-agent-v2/table
@load base/protocols/conn/contents
@load base/protocols/dns
@load base/bif
module DNStest;

export {
    # Create an ID for our new stream. By convention, this is
    # called "LOG".
    redef enum Log::ID += { LOG };

    # Define the record type that will contain the data to log.
    type Info: record {
        ts: time        &log;
        id: conn_id     &log; 
        notice : string &log;
    };
}   

redef record connection += {
    # By convention, the name of this new field is the lowercase name
    # of the module.
    dnstest: Info &optional;
};

type Columns: record{
    line_content : vector of string &log;
};

global resolved_addresses : table [addr] of string={
    [1.2.3.4] = "www.example.com"
};
global dns_server : set[addr];

event zeek_init(){
    Log::create_stream(DNStest::LOG, [$columns=Info, $path="dnstest"]);
}

#An event that can be handled to access the DNS::Info record as it is sent to the logging framework.
event DNS::log_dns(rec:DNS::Info){
    # builds pair of ip addr that gets send to name-server and the resolved answer string
    local query : string = rec$query;
    local answer : vector of string = rec$answers;
    local answer_address  = to_addr(answer[1]);
    resolved_addresses [answer_address] = query;
}

#Gets invoked when the result of a query "arrives". Adds result to corresponding table
event query_result(ctx: ZeekAgent::Context, data: Columns){
    local ip_address = to_addr(data$line_content[0]);
    local host_name = data$line_content[1];
    resolved_addresses[ip_address] = host_name + " from local hosts";
}

# Query the local host file via Zeek Agent
# 172.17.144.22 got added to hosts file manually for demonstration
function query_hosts_file(){
    local str_stmt_hosts = "SELECT columns FROM files_columns(\"/etc/hosts\",\"$1:text,$2:text\")";
    local query_event = query_result;
    local _schedule =  30 secs;
    local test_query_join = ZeekAgent::query([$sql_stmt=str_stmt_hosts,$event_=query_event,$schedule_=_schedule]);   
}

#check if destination ip-address got:
    # resolved
    # is a DNS-Server
    # is neither resolved before connection nor a DNS-Server
# and write to log
event check_resolve_table(c : connection){
    local destination_ip = c$id$resp_h;
    if(destination_ip !in resolved_addresses && destination_ip !in dns_server){
        local rec: DNStest::Info = [$ts=current_time(), $id=c$id, $notice="Connection without Resolve!"];
        # Store a copy of the data in the connection record so other
        # event handlers can access it.
        c$dnstest = rec;
        Log::write(DNStest::LOG, rec);
    }
}

# Generated when a connection’s internal state is about to be removed from memory.
# Zeek generates this event reliably once for every connection when it is about to delete the internal state.
event connection_state_remove(c: connection){
    query_hosts_file();
    local destination_ip = c$id$resp_h;
    local conn_service = c$service;
    # Add DNS-Server to set
    if("DNS" in conn_service){
        add dns_server[destination_ip];
    }
    # schedule resolve check so query result get added to the table before the connection gets checked 
    schedule 45 secs {check_resolve_table(c)}; 
}

# Generated at Zeek termination time.
event zeek_done(){
    print "Done";
}