(*
 * Copyright (C) 2013 Richard Mortier <mort@cantab.net>
 *                    Richard Clegg <richard@richardclegg.org>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *)

(** Definitions associated with flow-based processing of packet capture data. *)

(** Identifies a flow. *)

module type Key = sig

  (** Concrete flow type and pretty printers. *)
  type t
  val to_str: t -> string
  val to_string: t -> string

  (** [extract packet] returns the {! t} this packet matches. *)
  val extract: Packet.t -> t

  (** [compare a b] defines the usual comparator for {! t} so that we can
      use as a [Map] key. Should use the JS Core [with compare] functionality.
  *)
  val compare: t -> t -> int

end

(** Defines the state associated with an {! Key.t}.

    Really want to abstract across {! Key} not {! Key.t} so we can use the
    concrete [Key.extract packet] function.
*)

module type Value = sig

  (** State record indexed by a specific {! Key.t}, with pretty
      printers. *)
  type t
  val to_str: t -> string
  val to_string: t -> string

  (** [create ()] returns an empty flowstate record. *)
  val create: unit -> t

  (** [update flowstate packet] consumes [packet] updating [flowstate] as
      desired. *)
  val update: t -> Packet.t -> t

end

(** A map from {! Key.t} to {! Value.t}. *)

module type State = sig
  type t

  val to_str: t -> string
  val to_string: t -> string

  (** [update state packet] consumes [packet] updating [state] as desired. *)
  val update: t -> Packet.t -> t

  (** [create ()] returns an empty [State.t] record. *)
  val create: unit -> t

(*
  val all_keys: t -> Key.t list
  val lookup: t -> Key.t -> Value.t
  val remove: t -> Key.t -> t * Value.t
val fold: (State.t -> Packet.t -> State.t) -> State.t -> Packet.t list -> State.t
(* map, iter, etc... *)
*)

end

(** [fold consumef flowmap packets] applies the function [consumef] to take a
    [packet] from [packets], process it and accumulate results into [flowmap].

    Should be some kind of lazy [Packet.t] sequence not a [Packet.t list] --
    existing code provides this via the [iter] function with a caller-supplied
    [demuxf].
*)
