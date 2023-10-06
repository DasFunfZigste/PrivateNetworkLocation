#Scripts to use when you want to enrich conn log with a new field for custom location information for RFC1918 networks and not reuse the cc fields
#For Network locations, upload a file to the input framework of the sensor called localnetdef.db to assign addresses to names
#the format should be like this #fields<tab>localnet<tab>name<carriagereturn>192.168.2.0/24<tab>Washington and so on

module THETAD;

type Idx: record {
	localnet: subnet;
};
type Val: record {
	name: string &log;
};

global privnet: table[subnet] of Val = table();

redef record Conn::Info += {
	orig_location: string &log &optional;
	resp_location: string &log &optional;
};

event connection_state_remove(c: connection)
	{
	if ( c$id$orig_h in privnet )
		c$conn$orig_location = privnet[c$id$orig_h]$name;
		if ( c$id$resp_h in privnet )
		c$conn$resp_location = privnet[c$id$resp_h]$name;
	}

event zeek_init()
	{
	Input::add_table([
		$source="localnetdef.db",
		$name="privnet",
		$idx=Idx,
		$destination=privnet,
		$val=Val,
		$mode=Input::REREAD,
		$want_record=T
	]);
	}
