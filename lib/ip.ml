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

cenum protocol {
  ICMP =   1;
  TCP  =   6;
  UDP  =  17;
  GRE  =  47;
  ESP  =  50;
  AH   =  51;
  OSPF =  89
} as uint8_t

cenum port {
  DNS      =    53;
  BOOTPS   =    67;
  BOOTPC   =    68;
  HTTP     =    80;
  EPM      =   135;
  NBNS     =   137;
  NBSS     =   139;
  BGP      =   179;
  SMB      =   445;
  RTSP     =   554;
  RWS      =  1745;
  MSN      =  1863;
  XMPP_CLT =  5222; 
  XMPP_SVR =  5269 
} as uint16_t
 
let is_wellknown_port p  = ((    0 <= p) && (p <=  1023))
let is_registered_port p = (( 1024 <= p) && (p <= 49151))
let is_ephemeral_port p  = ((49152 <= p) && (p <= 65535))

cstruct ip4 {
  uint8_t  verhlen;
  uint8_t  tos;
  uint16_t len;
  uint16_t id;
  uint16_t flagoff;
  uint8_t  ttl;
  uint8_t  proto;
  uint16_t xsum;
  uint32_t src;
  uint32_t dst
} as big_endian

let get_ip4_ver  buf = (get_ip4_verhlen buf) lsr 4
let get_ip4_hlen buf = ((get_ip4_verhlen buf) land 0x0f) * 4

let get_ip4_offset buf = (get_ip4_flagoff buf) land 0x1fff

let get_ip4_flags buf = (get_ip4_flagoff buf) lsr 13
let is_df fs = (fs land 0x02 <> 0)
let is_mf fs = (fs land 0x01 <> 0)
let flags_to_string f = 
  sprintf "%s%s"
    (if is_df f then "DF" else "..")
    (if is_mf f then "MF" else "..")

let ip_to_string = Cstruct.ipv4_to_string

let to_str buf = 
  sprintf "%s,%s,%d, %d, %s,[%s]"
    (get_ip4_src buf |> ip_to_string)
    (get_ip4_dst buf |> ip_to_string)
    (get_ip4_proto buf)
    (get_ip4_len buf)
    (get_ip4_flags buf |> flags_to_string)
    "OPTS-NOT-PARSED"

let to_string buf = 
  sprintf "ver:%d hlen:%d tos:%02x len:%d id:%d flags:%s offset:%d ttl:%d proto:%d xsum:%04x src:%s dst:%s opts:%s"
    (get_ip4_ver buf)
    (get_ip4_hlen buf)
    (get_ip4_tos buf)
    (get_ip4_len buf)
    (get_ip4_id buf)
    (get_ip4_flags buf |> flags_to_string)
    (get_ip4_offset buf)
    (get_ip4_ttl buf)
    (get_ip4_proto buf)
    (get_ip4_xsum buf)
    (get_ip4_src buf |> ip_to_string)
    (get_ip4_dst buf |> ip_to_string)
    "OPTS-NOT-PARSED"
