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

open Packet
open Printf
open Flow

module Unidir : Key = struct

  type t = (int32 * int * int32 * int)

  let to_str (tx, txpt, rx, rxpt) =
    sprintf "%s,%d, %s,%d"
      (Ip4.ip_to_string tx) txpt (Ip4.ip_to_string rx) rxpt

  let to_string (tx, txpt, rx, rxpt) =
    sprintf "%s/%d -> %s/%d"
      (Ip4.ip_to_string tx) txpt (Ip4.ip_to_string rx) rxpt

  let unmatched = (0l, 0, 0l, 0)

  let extract = function
    | ETH(_, IP4(ih, TCP4(th, _))) ->
      (ih.Ip4.src, th.Tcp4.srcpt, ih.Ip4.dst, th.Tcp4.dstpt)
    | ETH(_, IP4(ih, UDP4(th, _))) ->
      (ih.Ip4.src, th.Udp4.srcpt, ih.Ip4.dst, th.Udp4.dstpt)

    | _ -> unmatched

  let compare x y = compare x y

end

module Bidir : Key = struct

  type t = (int32 * int * int32 * int)

  let to_str (tx, txpt, rx, rxpt) =
    sprintf "%s,%d, %s,%d"
      (Ip4.ip_to_string tx) txpt (Ip4.ip_to_string rx) rxpt

  let to_string (tx, txpt, rx, rxpt) =
    sprintf "%s/%d -- %s/%d"
      (Ip4.ip_to_string tx) txpt (Ip4.ip_to_string rx) rxpt

  let unmatched = (0l, 0, 0l, 0)

  let extract p =
    let (tx, txpt, rx, rxpt) = match p with
      | ETH(_, IP4(ih, TCP4(th, _))) ->
        (ih.Ip4.src, th.Tcp4.srcpt, ih.Ip4.dst, th.Tcp4.dstpt)
      | ETH(_, IP4(ih, UDP4(th, _))) ->
        (ih.Ip4.src, th.Udp4.srcpt, ih.Ip4.dst, th.Udp4.dstpt)
      | _ -> unmatched
    in
    if (tx < rx) || (tx == rx && txpt <= rxpt) then
      (tx, txpt, rx, rxpt)
    else
      (rx, rxpt, tx, txpt)

  let compare x y = compare x y

end

(*
module Value = struct

end
*)

(*
module State = struct

  module FlowMap = Map.Make(Flow.Key)
  type t = FlowMap

  let to_str flowmap = ""
  let to_string flowmap = ""

  let update flowmap packet = flowmap

  let create () = FlowMap.empty

  let all_keys flowmap = []

  let lookup flowmap key = Flow.Value.create ()

  let remove flowmap key = (key, Flow.Value.create ())

end

let fold f flowmap packets = flowmap
*)
