val version: string

val usecs_to_string: int64 -> string

type h = {
  usecs: int64;
  caplen: int;
  len: int;
}

val to_str: h -> string
val to_string: h -> string

type t = PKT of h * Ps.Packet.t * Cstruct.t
