################################################################################
#
# @author electron<937431539@qq.com>
# @date   2014/10/07
#
################################################################################

/ip firewall mangle

:local lineNum 	4
:local lanInt 		eth5-master
:local pccType 		both-addresses-and-ports
:local dscpList 	(46, 38, 30, 22, 14)
:local tmp

add action=jump chain=prerouting comment="Jump PCC" connection-mark=no-mark dst-address-type=!local \
	in-interface=$lanInt jump-target=PCC_CHAIN disabled=yes

# PCC·ÖÁ÷
:for i from=1 to=$lineNum do={
	:set tmp ($pccType . ":" . $lineNum . "/" . ($i - 1))
	add action=mark-connection chain=PCC_CHAIN disabled=yes \
		new-connection-mark=($i . "_conn") \
		per-connection-classifier=$tmp
}
:for i from=1 to=$lineNum do={
	add action=mark-routing chain=prerouting disabled=yes \
		in-interface=$lanInt connection-mark=($i . "_conn") new-routing-mark=($i . "_route")
}

#
:for i from=1 to=$lineNum do={
	:foreach dscp in=$dscpList do={
		add action=mark-routing chain=prerouting disable=yes \
			connection-mark=("pcc" . $i . "_dscp" . $dscp . "_conn") \
			in-interface=$lanInt new-routing-mark=($i . "_route")
	}
}

:for i from=1 to=$lineNum do={
	:foreach dscp in=$dscpList do={
		:set tmp ("pcc" . $i . "_dscp" . $dscp . "_conn")
		add action=mark-connection chain=prerouting connection-mark=($i . "_conn") disabled=yes \
			dscp=$dscp new-connection-mark=$tmp
		add action=mark-packet chain=prerouting connection-mark=$tmp disabled=yes\
			new-packet-mark=("pcc" . $i . "_dscp" . $dscp . "_packet") passthrough=no
	}
}
