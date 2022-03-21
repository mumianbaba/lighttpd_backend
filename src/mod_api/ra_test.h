
#define s_ok  "{\
	\"statusCode\": 200,\
	\"statusDesc\": \"OK\",\
	\"timestamp\": \"1994-11-04 19:45:25\"\
}"

#define s_failed  "{\
	\"statusCode\": 400,\
	\"statusDesc\": \"Failed\",\
	\"timestamp\": \"1994-11-04 19:45:25\"\
}"

///api/network/wanConf
#define s_wanConf  "{\
	\"statusCode\": 200,\
	\"statusDesc\": \"OK\",\
	\"timestamp\": \"2006-12-30 05:58:36\",\
	\"body\": {\
		\"proto\": \"static\",\
		\"netmask\": \"255.255.252.0\",\
		\"gateway\": \"192.168.18.1\",\
		\"dns1\": \"8.8.8.8\",\
		\"dns2\": \"114.114.114.114\",\
		\"staticDNSEnable\": 1,\
		\"wireWanEnable\": 1,\
		\"macAddress\": \"10:22:33:44:55:66\",\
		\"ip\": \"192.168.18.74\"\
	}\
}"

///api/network/lanConf
#define s_lanConf  "{\
	\"statusCode\": 200,\
	\"statusDesc\": \"OK\",\
	\"timestamp\": \"2012-10-16 07:05:50\",\
	\"body\": {\
		\"ipStart\": 100,\
		\"ip\": \"192.168.124.1\",\
		\"netmask\": \"255.255.255.0\",\
		\"dhcpServerEnable\": 1,\
		\"addrLease\": 24,\
		\"domainAccess\": \"rtu.com\",\
		\"macAddress\": \"10:22:33:44:55:66\",\
		\"ipEnd\": 200\
	}\
}"

////api/network/lanDeviceList
#define s_lanDeviceList  "{ \
	\"statusCode\": 200,\
	\"statusDesc\": \"OK\",\
	\"timestamp\": \"2000-12-16 09:54:35\",\
	\"body\": {\
		\"number\": 3,\
		\"pageSize\": 10,\
		\"pageNum\": 1,\
		\"list\": [{\
				\"name\": \"张三\",\
				\"macAddress\": \"10:22:33:44:55:66\",\
				\"uptime\": 1400,\
				\"ip\": \"240.173.248.161\"\
			},\
			{\
				\"name\": \"RTu-121\",\
				\"macAddress\": \"10:22:33:44:55:66\",\
				\"uptime\": 50000,\
				\"ip\": \"66.176.69.145\"\
			},\
			{\
				\"name\": \"Linov-1212\",\
				\"macAddress\": \"10:22:33:44:55:66\",\
				\"uptime\": 600000,\
				\"ip\": \"142.80.217.63\"\
			}\
		]\
	}\
}"

///api/network/mobileInfo
#define s_mobileInfo  "{\
	\"statusCode\": 200,\
	\"statusDesc\": \"OK\",\
	\"timestamp\": \"1997-08-29 09:31:23\",\
	\"body\": {\
		\"ip\": \"10.0.0.64\",\
		\"apn\": \"CMCC\",\
		\"imei\": \"12123243254563456423\",\
		\"operator\": \"CMCC\",\
		\"registerState\": \"successful\",\
		\"link\": \"up\",\
		\"signalStrength\": \"high\",\
		\"signalType\": \"4g\",\
		\"mobileUser\": \"admin\",\
		\"mobilePw\": \"181867\",\
		\"mobileEnable\": 1\
	}\
}"


///api/network/networkInfo
#define s_networkInfo  "{\
	\"statusCode\": 200,\
	\"statusDesc\": \"OK\",\
	\"timestamp\": \"2006-10-19 08:16:16\",\
	\"body\": {\
		\"wan\": {\
			\"proto\": \"static\",\
			\"netmask\": \"255.255.252.0\",\
			\"ip\": \"192.168.18.89\",\
			\"gateway\": \"192.168.18.1\",\
			\"dns1\": \"8.8.8.8\",\
			\"dns2\": \"114.114.114.114\",\
			\"macAddress\": \"10:22:33:44:55:66\",\
			\"upstreamPort\": \"mobileNet\"\
		},\
		\"lan\": {\
			\"ipStart\": 100,\
			\"ipEnd\": 200,\
			\"ip\": \"192.168.124.1\",\
			\"netmask\": \"255.255.255.0\",\
			\"macAddress\": \"10:22:33:44:55:66\"\
		}\
	}\
}"


///api/firewall/firewallConf
#define s_firewallConf  "{\
	\"statusCode\": 200,\
	\"statusDesc\": \"OK\",\
	\"timestamp\": \"1972-03-07 19:34:22\",\
	\"body\": {\
		\"firewallEnable\": 1\
	}\
}"


///api/firewall/macFilter
#define s_macFilter  "{\
	\"timestamp\": \"1971-09-20 06:05:04\",\
	\"statusCode\": 200,\
	\"statusDesc\": \"OK\",\
	\"body\": {\
		\"number\": 2,\
		\"filterMode\": \"blacklist\",\
		\"list\": [{\
				\"devName\": \"jerry\",\
				\"macAddress\": \"90:88:77:66:55:44\"\
			},\
			{\
				\"macAddress\": \"tom\",\
				\"devName\": \"40:55:66:77:88:99\"\
			}\
		]\
	}\
}"


///api/firewall/portFilter
#define s_portFilter  "{\
	\"timestamp\": \"1996-05-26 19:38:06\",\
	\"statusCode\": 200,\
	\"statusDesc\": \"OK\",\
	\"body\": {\
		\"number\": 21,\
		\"portFilterEnable\": 1,\
		\"list\": [{\
				\"portStart\": 80,\
				\"description\": \"web port\",\
				\"portEnd\": 32\
			},\
			{\
				\"portStart\": 8080,\
				\"description\": \"xxx aplication port\",\
				\"portEnd\": 8080\
			},\
			{\
				\"portStart\": 8088,\
				\"description\": \"yyyy aplocation port\",\
				\"portEnd\": 8088\
			}\
		]\
	}\
}"
