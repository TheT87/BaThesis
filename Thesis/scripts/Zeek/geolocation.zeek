module GeoLogTest;

export {
    # Create an ID for our new stream. By convention, this is
    # called "LOG".
    redef enum Log::ID += { LOG };

    # Define the record type that will contain the data to log.
    type Info: record {
        ts: time        &log;
        rts : string 	&log;
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
global threshold : int; 
global night_time_decrease : int;
global day_time_increase : int;
#const home_country = "DE";
#const home_latitude = 51.025889;
const home_longitude = 13.723376;
const closing_time = 19;
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
	print(c_time);
	threshold = 10;
	night_time_decrease = 10;
	day_time_increase = 10;
	if(c_time< opening_time || c_time > closing_time )
		threshold = threshold-night_time_decrease;
	else 
		threshold = threshold+day_time_increase;
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
	print(id_string(c$id));
	if (number_of_connections > threshold){
		local rec: GeoLogTest::Info = [$ts=current_time(),$rts=strftime("%H:%M:%S",network_time()), $id=c$id, $notice="Threshold exceeded"];
		# Store a copy of the data in the connection record so other
    	# event handlers can access it.
    	c$geologtest = rec;
		Log::write(GeoLogTest::LOG, rec);
		break;
	}
}

event zeek_init(){
	Log::create_stream(GeoLogTest::LOG, [$columns=Info, $path="geologtest"]);
}


event connection_attempt(c: connection){
	local origin = geolocation(c);
	local origin_time = time_at_geolocation(origin);
	local connection_attempt_threshold = set_threshold(origin_time);
	local count_connection_attempts_c = number_of_connection_attempts(c);
	log_exceeded_ips(c,connection_attempt_threshold,count_connection_attempts_c);
}