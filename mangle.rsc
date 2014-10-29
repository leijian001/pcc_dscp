################################################################################
#
# @author electron<937431539@qq.com>
# @date   2014/10/29
#
################################################################################

/ip firewall mangle

:local lineNum 		4
:local lanIP 		vip
:local pccType 		both-addresses-and-ports
:local dscpList 	(46, 38, 30, 22, 14)
:local tmp

add action=jump chain=prerouting comment="Jump PCC" connection-mark=no-mark dst-address-type=!local \
	src-address-list=$lanIP jump-target=PCC_CHAIN disabled=yes

# PCC分流
:for i from=1 to=$lineNum do={
	:set tmp ($pccType . ":" . $lineNum . "/" . ($i - 1))
	add action=mark-connection chain=PCC_CHAIN disabled=yes \
		new-connection-mark=($i . "_conn") \
		per-connection-classifier=$tmp
}
:for i from=1 to=$lineNum do={
	add action=mark-routing chain=prerouting disabled=yes \
		src-address-list=$lanIP connection-mark=($i . "_conn") new-routing-mark=($i . "_route")
}


:for i from=1 to=$lineNum do={
	:foreach dscp in=$dscpList do={
		add action=mark-routing chain=prerouting disable=yes \
			connection-mark=("pcc" . $i . "_dscp" . $dscp . "_conn") \
			src-address-list=$lanIP new-routing-mark=($i . "_route")
	}
}

:for i from=1 to=$lineNum do={
	:foreach dscp in=$dscpList do={
		:set tmp ("pcc" . $i . "_dscp" . $dscp . "_conn")
		add action=mark-connection chain=prerouting connection-mark=($i . "_conn") disabled=yes \
			dscp=$dscp new-connection-mark=$tmp
		add action=mark-packet chain=prerouting connection-mark=$tmp disabled=yes src-address-list=$lanIP \
			new-packet-mark=("pcc" . $i . "_dscp" . $dscp . "_up_packet") passthrough=no
		add action=mark-packet chain=prerouting connection-mark=$tmp disabled=yes \
			new-packet-mark=("pcc" . $i . "_dscp" . $dscp . "_down_packet") passthrough=no
	}
}
