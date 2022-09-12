
@load base/utils/time


module GeoLogTest;

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
    geologtest: Info &optional;
};

global ip_addresses : table[addr] of int;
global threshold = 20.0 ;
#const home_country = "DE";
#const home_latitude = 51.025889;
const home_longitude = 13.723376;
const closing_time = 18;
const opening_time = 7;

function geolocation(c: connection):double{
	local origin_country = lookup_location(c$id$orig_h)$country_code;
	local origin_longitude = lookup_location(c$id$orig_h)$longitude;
	return origin_longitude;
}

function time_at_geolocation(longitude: double): int{
	#	1° of longitude is 4 minutes of time
	local time_difference  = (longitude - home_longitude)*240;
	local double_time_difference = time_to_double(network_time()) + time_difference;
	local epoch_time_difference = double_to_time(double_time_difference);
	local time_at_origin  = strftime("%H", epoch_time_difference);
	local useable_time_at_origin = to_int(time_at_origin);
	return useable_time_at_origin;
}

function set_threshold(c_time: int): double{
	if(c_time< opening_time || c_time > closing_time )
		threshold = threshold*0.5;
	else 
		threshold = threshold*1.1;
	return threshold;

}

function number_of_connection_attempts(c:connection): int{
	if (c$id$orig_h in ip_addresses){
		local val = ip_addresses[c$id$orig_h];
		ip_addresses[c$id$orig_h] = val+1;
			
	} else {
		ip_addresses[c$id$orig_h] = 1;
	}
	return ip_addresses[c$id$orig_h];
}

function log_exceeded_ips (c: connection, threshold: double, number_of_connections: int){
	if (number_of_connections > threshold){
		local rec: GeoLogTest::Info = [$ts=network_time(), $id=c$id, $notice="Threshold exceeded"];
		# Store a copy of the data in the connection record so other
    	# event handlers can access it.
    	c$geologtest = rec;
		Log::write(GeoLogTest::LOG, rec);
	}
}

event zeek_init(){
	local debug_plugin = NetControl::create_debug(T);
	NetControl::activate(debug_plugin, 0);
	Log::create_stream(GeoLogTest::LOG, [$columns=Info, $path="geologtest"]);
}


event connection_attempt(c: connection){

	local origin = geolocation(c);
	local origin_time = time_at_geolocation(origin);
	local connection_attempt_threshold = set_threshold(origin_time);
	local count_connection_attempts_c = number_of_connection_attempts(c);
	log_exceeded_ips(c,connection_attempt_threshold,count_connection_attempts_c);
	
}