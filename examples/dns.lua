local dpdk		= require "dpdk"
local memory	= require "memory"
local device	= require "device"
local stats		= require "stats"


function master(txPorts, domain, minIp, numIps, rate)
	if not txPorts then
		printf("usage: txPort1[,txPort2[,...]] [ domain, minIP numIPs rate]")
		return
	end
	txPorts = tostring(txPorts)
	domain = domain or "test.example.com"	
	minIp = minIp or "10.0.0.1"
	numIps = numIps or 100
	rate = rate or 0
	for currentTxPort in txPorts:gmatch("(%d+),?") do
		currentTxPort = tonumber(currentTxPort) 
		local txDev = device.config({ port = currentTxPort })
		txDev:wait()
		txDev:getTxQueue(0):setRate(rate)
		dpdk.launchLua("loadSlave", currentTxPort, 0, domain, minIp, numIps)
	end
	dpdk.waitForSlaves()
end

function loadSlave(port, queue, domain, minA, numIPs)
	--- parse and check ip addresses

	local domain_label = '' 
	local domain = domain
	
	for i in string.gmatch(domain, "%w+") do
                domain_label = domain_label  .. string.len(i) .. i
 	end
	
	domain_label = domain_label .. '0'
	local len = string.len(domain_label)

	local minIP, ipv4 = parseIPAddress(minA)
	if minIP then
		printf("INFO: Detected an %s address.", minIP and "IPv4" or "IPv6")
	else
		errorf("ERROR: Invalid minIP: %s", minA)
	end

	-- min TCP packet size for IPv6 is 74 bytes (+ CRC)
	--local packetLen = ipv4 and 60 or 74
	local packetLen = ipv4 and (54 + len + 15) or 60 
	
	--continue normally
	local queue = device.get(port):getTxQueue(queue)
	local mem = memory.createMemPool(function(buf)
		buf:getUdpPacket(ipv4):fill{ 
			ethSrc="a0:36:9f:a1:4d:6d", ethDst="52:54:00:2E:62:A2",
			ip4Dst="10.9.3.6", 
			ip6Dst="fd06::1",
			udpDst="53",
			udpSrc="1029",
			pktLength=packetLen }

		local pkt = buf:getUdpPacket(ipv4)

                -- flags 0x0120, when convert to decimal, take care indianess, thus should be 0x2001 = 8193
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

		local domain_start = 6

		for i in string.gmatch(domain_label, "%w%w?") do
        		local d_hex = ''
        		local c_hex = ''
        		local hex = ''
        		local t = {}

        		-- if the final character end with single, append 0
        		if (string.len(i) < 2 ) then
                		i = i .. '0'
        		end

        		for k in string.gmatch(i, "%w") do

                		if (string.match(k, "%d")) then
                        		d_hex = d_hex .. string.format("%x", k, 16)
                        		if (tonumber(k) < 16) then
                                		d_hex = '0' .. d_hex
                        		end
                        		t[#t + 1] = d_hex
                		else
                        		local dec = string.byte(k, 1,  16)
                        		c_hex = string.format("%x", dec)
                        		t[#t + 1] = c_hex
                		end

        		end


        		hex = t[2] .. t[1]
			
			pkt.payload.uint16[domain_start] = tonumber(hex, 16)  
			domain_start = domain_start + 1

		end


		if ( len % 2 ~= 0) then
			-- 0x0001 type A
			pkt.payload.uint16[domain_start] = 1  
			domain_start = domain_start + 1
			-- 0x0001 class IN
			pkt.payload.uint16[domain_start] = 1  
			domain_start = domain_start + 1
			-- 0x0029 -> endian -> 0x2900
			pkt.payload.uint16[domain_start] = 10496  
			domain_start = domain_start + 1
			-- 0x1000 -> 0010
			pkt.payload.uint16[domain_start] = 16  
			domain_start = domain_start + 1
			pkt.payload.uint16[domain_start] = 0  
			domain_start = domain_start + 1
			pkt.payload.uint16[domain_start] = 0  
			domain_start = domain_start + 1
			pkt.payload.uint16[domain_start] = 0
		else
			-- 0x0001 type A
			pkt.payload.uint16[domain_start] = 256  
			domain_start = domain_start + 1
			-- 0x0001 class IN
			pkt.payload.uint16[domain_start] = 256  
			domain_start = domain_start + 1
		end
			
		
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


