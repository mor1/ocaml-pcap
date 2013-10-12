open Cstruct
open Capture.Pcap


module PackedState :
	sig
		type t
		val create :  unit -> t
        val dump : t -> unit
	end

module State :
	sig
		type t
		val create : unit -> t
        val dump : t -> unit
	end

module Genstate:
sig
	type genstate = Packed of PackedState.t | Full of State.t
end

val pkt_process_flow : State.t -> Capture.Pcap.t -> State.t
val pkt_process_packed_flow : PackedState.t -> Capture.Pcap.t -> PackedState.t
val	filename_to_buf : string -> Cstruct.t
val parse : Genstate.genstate -> Cstruct.t -> unit




