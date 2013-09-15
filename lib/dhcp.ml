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

open Operators
open Printf

cstruct dhcp4 {
  uint8_t  op;
  uint8_t  htype;
  uint8_t  hlen;
  uint8_t  hops;
  uint32_t xid;
  uint16_t secs;
  uint16_t flags;

  uint32_t ciaddr;
  uint32_t yiaddr;
  uint32_t siaddr;
  uint32_t giaddr;
  
  uint8_t chaddr[16];
  uint8_t sname[64];
  uint8_t file[128]
} as big_endian

type h = {
  op: int;
  htype: int;
  xid: int32;
}

let h buf = {
  op = get_dhcp4_op buf;
  htype = get_dhcp4_htype buf;
  xid = get_dhcp4_xid buf;
}

let flags_to_string f = 
  let is_bcast f = f &&& 0x8000l <> 0l in
  sprintf "%s" (if is_bcast f then "B" else ".")

let h_to_str h =
  sprintf "%d,%d, %08lx"
    h.op h.htype h.xid

(* let to_str h =  *)
(*   sprintf "%d,%d,%d,%d, %08x,%u,%s, %s,%s,%s,%s, '%s'" *)
(*      h.op *)
(*     h.htype *)
(*     h.hlen *)
(*     h.hops *)
    
(*     h.xid *)
(*     (int h.secs) *)
(*     (dhcp_flags_to_string  h.flags) *)
    
(*     (ip_addr_to_string h.ciaddr) *)
(*     (ip_addr_to_string h.yiaddr) *)
(*     (ip_addr_to_string h.siaddr) *)
(*     (ip_addr_to_string h.giaddr) *)

(*     (eth_addr_to_string (Array.sub h.chaddr 0 eth_addr_len)) *)

let h_to_string h =
  sprintf "%d,%d, %08lx"
    h.op h.htype h.xid
                      
(* let to_string h =  *)
(*   sprintf "%d,%d,%d,%d, %08x,%u,%s, %s,%s,%s,%s, '%s','%s','%s'" *)
(*     (int h.op) *)
(*     (int h.htype) *)
(*     (int h.hlen) *)
(*     (int h.hops) *)
    
(*     h.xid *)
(*     (int h.secs) *)
(*     (verbose_dhcp_flags_to_string h.flags) *)
    
(*     (ip_addr_to_string h.ciaddr) *)
(*     (ip_addr_to_string h.yiaddr) *)
(*     (ip_addr_to_string h.siaddr) *)
(*     (ip_addr_to_string h.giaddr) *)

(*     (eth_addr_to_string (Array.sub h.chaddr 0 eth_addr_len)) *)
(*     (bytes_to_hex_string h.sname) *)
(*     (bytes_to_hex_string h.file) *)

type p = 
  | UNKNOWN of Cstruct.t
type t = h * p

let to_str (h, p) = sprintf "DHCP(%s)" (h_to_str h)
let to_string (h, p) = sprintf "DHCP(%s)" (h_to_string h)
