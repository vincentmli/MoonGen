local dpdk		= require "dpdk"
local memory	= require "memory"
local device	= require "device"
local stats		= require "stats"


function master(txPorts, minIp, numIps, rate)
	if not txPorts then
		printf("usage: txPort1[,txPort2[,...]] [minIP numIPs rate]")
		return
	end
	txPorts = tostring(txPorts)
	minIp = minIp or "10.0.0.1"
	numIps = numIps or 100
	rate = rate or 0
	for currentTxPort in txPorts:gmatch("(%d+),?") do
		currentTxPort = tonumber(currentTxPort) 
		local txDev = device.config({ port = currentTxPort })
		txDev:wait()
		txDev:getTxQueue(0):setRate(rate)
		dpdk.launchLua("loadSlave", currentTxPort, 0, minIp, numIps)
	end
	dpdk.waitForSlaves()
end

function loadSlave(port, queue, minA, numIPs)
	--- parse and check ip addresses

	local minIP, ipv4 = parseIPAddress(minA)
	if minIP then
		printf("INFO: Detected an %s address.", minIP and "IPv4" or "IPv6")
	else
		errorf("ERROR: Invalid minIP: %s", minA)
	end

	-- min TCP packet size for IPv6 is 74 bytes (+ CRC)
	--local packetLen = ipv4 and 60 or 74
	local packetLen = ipv4 and 86 or 60 
	
	--continue normally
	local queue = device.get(port):getTxQueue(queue)
	local mem = memory.createMemPool(function(buf)
		buf:getUdpPacket(ipv4):fill{ 
			ethSrc="e8:ea:6a:06:1b:1b", ethDst="00:23:E9:49:37:03", 
			--- ip4Dst="10.9.1.2", 
			ip4Dst="10.3.3.248", 
			ip6Dst="fd06::1",
			udpDst="53",
			udpSrc="1029",
			pktLength=packetLen }
	end)

	local lastPrint = dpdk.getTime()
	local totalSent = 0
	local lastTotal = 0
	local lastSent = 0
	local bufs = mem:bufArray(128)
	local counter = 0
	local c = 0

	local txStats = stats:newDevTxCounter(queue, "plain")
	while dpdk.running() do
		-- faill packets and set their size 
		bufs:alloc(packetLen)
		for i, buf in ipairs(bufs) do 			
			local pkt = buf:getUdpPacket(ipv4)
			
			--increment IP
			if ipv4 then
				pkt.ip4.src:set(minIP)
				pkt.ip4.src:add(counter)
				--random udp source port
				pkt.udp.src = math.random(0, 2^16 - 1)
				-- random dns query id 
				pkt.payload.uint16[0] = math.random(0, 2^16 - 1) 
				-- flags 0x0120, when convert to decimal, Linux is little endian, so convert network order big endian to little endian thus: 0x2001 = 8193
				pkt.payload.uint16[1] = 8193  
				-- query count 0x0001, thus convert 0x0100 = 256
				pkt.payload.uint16[2] = 256  
				--pkt.payload.uint16[2] = 768  
				-- Answer RRs
				pkt.payload.uint16[3] = 0  
				-- Authority RRs
				pkt.payload.uint16[4] = 0  
				-- Aditional RRs
				pkt.payload.uint16[5] = 256  
				-- 3www7example3com type A class IN
				-- 0x7703 w 
				pkt.payload.uint16[6] = 30467  
				-- 0x7777 ww
				pkt.payload.uint16[7] = 30583  
 				-- 0x6507 e 
				pkt.payload.uint16[8] = 25863  
				-- 0x6178 xa 
				pkt.payload.uint16[9] = 24952  
				-- 0x706d mp 
				--pkt.payload.uint16[10] =  math.random(0, 2^16 - 1)
				pkt.payload.uint16[10] = 28781  
		--pkt.payload.uint16[10] = tonumber( ( string.format("%x", math.random(97,122)) .. string.format("%x", math.random(97,122)) ), 16 )
				-- 0x656c le 
				pkt.payload.uint16[11] = 25964  
				-- 0x6303 c 
				pkt.payload.uint16[12] = 25347  
				-- 0x6d6f om
				pkt.payload.uint16[13] = 28015  
				-- 0x0000
				pkt.payload.uint16[14] = 0  
				-- 0x0001 type A
				pkt.payload.uint16[15] = 1  
				-- 0x0001 class IN
				pkt.payload.uint16[16] = 1  
				-- 0x0029 -> endian -> 0x2900
				pkt.payload.uint16[17] = 10496  
				-- 0x1000 -> 0010
				pkt.payload.uint16[18] = 16  
				pkt.payload.uint16[19] = 0  
				pkt.payload.uint16[20] = 0  
				pkt.payload.uint16[21] = 0  
			else
				pkt.ip6.src:set(minIP)
				pkt.ip6.src:add(counter)
			end
			counter = incAndWrap(counter, numIPs)

			-- dump first 3 packets
			if c < 3 then
				buf:dump()
				c = c + 1
			end
		end 
		--offload checksums to NIC
		bufs:offloadUdpChecksums(ipv4)
		
		totalSent = totalSent + queue:send(bufs)
		txStats:update()
	end
	txStats:finalize()
end


