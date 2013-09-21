
type t = 
  | ETH  of Ethernet.h * t
  | IP4 of Ip4.h * t
  | TCP4  of Tcp4.h * t
  | UDP4  of Udp4.h * t
      
  | DHCP of Dhcp4.t
  | ARP of Arp.t

  | DATA of Cstruct.t
  | ERROR of Cstruct.t
  | DROP

val to_str: t -> string
val to_string: t -> string
