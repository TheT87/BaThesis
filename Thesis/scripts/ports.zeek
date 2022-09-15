@load site/packages/zeek-agent-v2
@load site/packages/zeek-agent-v2/framework/main
@load site/packages/zeek-agent-v2/table
@load site/zeek-agent-v2
@load site/zeek-agent-v2/framework
@load site/zeek-agent-v2/table


module Querytest;

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

#global hid = "tobi-ODROID-H2";

redef record connection += {
    # By convention, the name of this new field is the lowercase name
    # of the module.
    querytest: Info &optional;
};

type Columns: record {
    name: string &optional &log; ##< short name
    is_admin: bool &optional &log; ##< 1 if user has adminstrative privileges
    process: string &optional &log; ##< name of process holding socket
    protocol: count &optional &log; ##< transport protocol
    local_addr: addr &optional &log; ##< local IP address
    local_port: count &optional &log; ##< local port number
    remote_addr: addr &optional &log; ##< remote IP address
    remote_port: count &optional &log; ##< remote port number
};


global local_ports : table[int] of string ={
        [80] = "http",
        [22] = "ssh",
        [25552] = "application_1",
        #[42124] = "application_2",
        #[42125] = "application_3"  

    };
global allowed_ports : table[int] of string = {
        [42124] = "application_2",
        [42125] = "application_3" 
    };

function check_outgoing_connection(c:connection){
    local _port = port_to_count(c$id$orig_p);
    if(_port !in local_ports){
        local rec: Querytest::Info = [$ts=current_time(), $id=c$id, $notice="No Application running on this port"];
        # Store a copy of the data in the connection record so other
        # event handlers can access it.
        c$querytest = rec;
        Log::write(Querytest::LOG, rec);
    }else{
        print "Included: ";
        print _port;
        local rec_2: Querytest::Info = [$ts=current_time(), $id=c$id, $notice="Working"];
        # Store a copy of the data in the connection record so other
        # event handlers can access it.
        c$querytest = rec_2;
        Log::write(Querytest::LOG, rec_2);
    
    }
}

event users_result(ctx: ZeekAgent::Context, data: Columns){
    #print data;
    local new_entry : count;
    local connection_port = data$remote_port;
    new_entry = connection_port;
    print new_entry;
    local_ports[new_entry] = data$name;
   

}

event zeek_init(){
	Log::create_stream(Querytest::LOG, [$columns=Info, $path="querytest"]);

    local str_stmt_processes = "SELECT name,pid,uid,gid,ppid,priority,startup FROM processes";
    local str_stmt_sockets = "SELECT process, local_addr, local_port FROM sockets";
    local str_stmt_join = "SELECT users.name, users.is_admin, sockets.process, sockets.protocol, sockets.local_addr, sockets.local_port, sockets.remote_addr, sockets.remote_port FROM users JOIN processes ON users.uid=processes.uid JOIN sockets ON sockets.pid=processes.pid";
    local query_event = users_result;
    local _schedule = 1 secs;
    #local test_query_processes = ZeekAgent::query([$sql_stmt=str_stmt_processes,$event_=processes_result,$schedule_=_schedule]);
    #local test_query_sockets = ZeekAgent::query([$sql_stmt=str_stmt_sockets,$event_=sockets_result,$schedule_=_schedule]);
    local test_query_join = ZeekAgent::query([$sql_stmt=str_stmt_join,$event_=query_event,$schedule_=_schedule]);
    
    }

event connection_state_remove(c: connection){

    check_outgoing_connection(c);
    print "Checked";
    print c$id$orig_h;
}

event zeek_done(){
    
    print(local_ports);
    print(" ");
    print allowed_ports;
    print "Done";
}