open Printf

let version = "0.4.0"


let usecs_to_string ts =
  let secs = Int64.(div ts 1_000_000_L |> to_int32) in
  let usecs = Int64.(rem ts 1_000_000_L |> to_int32) in
  sprintf "%lu.%06lu" secs usecs


type h = {
  usecs: int64;
  caplen: int;
  len: int;
}

let to_str h =
  sprintf "%s, %u,%u" (usecs_to_string h.usecs) h.caplen h.len

let to_string h =
  sprintf "time:%s caplen:%u len:%u" (usecs_to_string h.usecs) h.caplen h.len

type t = PKT of h * Ps.Packet.t * Cstruct.t
