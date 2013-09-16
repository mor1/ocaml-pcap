(*
 * Copyright (c) 2013 Richard Mortier <mort@cantab.net>
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

(** break the cycle: Packet depends on various formats (Ethernet, etc); but
    demux results in a Packet.t element, hence can't include demux functions
    in the format modules themselves. could put them in Packet but seems
    cleaner to break them out. *)

open Packet

let data_demux _ buf = DATA buf

let udp4_demux st buf = 
  let open Udp4 in
  let uh = h buf in
  let buf = Cstruct.shift buf sizeof_udp4 in
  let payload p =
    let open Ip4 in
    match int_to_port p with
      | None -> data_demux st buf
      | Some p -> match p with
          | BOOTPS | BOOTPC
            -> Dhcp4.(DHCP(h buf, 
                           UNKNOWN (Cstruct.shift buf sizeof_dhcp4)))
          | _ -> data_demux st buf
  in
  UDP4(uh, payload uh.dstpt)
    
let tcp4_demux st buf = 
  let open Tcp4 in
  let th = h buf in
  TCP4(th, data_demux st (Cstruct.shift buf sizeof_tcp4))

let ip_demux st buf = 
  let open Ip4 in
  let ih = h buf in
  let ipproto_demux t = 
    match int_to_protocol t with
      | None -> data_demux
      | Some t -> match t with
          | UDP -> udp4_demux 
          | TCP -> tcp4_demux
          | _ -> data_demux
  in
  IP4(ih, (ipproto_demux ih.proto) st (Cstruct.shift buf sizeof_ip4))

let eth_demux st buf = 
  let open Ethernet in
  let eh = h buf in
  let ethertype_demux t = 
    match int_to_ethertype t with
      | None -> data_demux
      | Some t -> match t with
          | IP4 -> ip_demux
          | _ -> data_demux
  in
  ETH(eh, (ethertype_demux eh.ethertype) st (Cstruct.shift buf sizeof_ethernet))
