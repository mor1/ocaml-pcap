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

cstruct tcp4 {
  uint16_t srcpt;
  uint16_t dstpt;
  uint32_t seqno;
  uint32_t ackno;
  uint16_t flagoff;
  uint16_t window;
  uint16_t xsum;
  uint16_t urgent
} as big_endian

let get_tcp4_offset buf = ((get_tcp4_flagoff buf) land 0xf000) lsr 12
let get_tcp4_flags buf = (get_tcp4_flagoff buf) land 0x003f

let is_fin fs = fs land 0x01 <> 0
let is_syn fs = fs land 0x02 <> 0
let is_rst fs = fs land 0x04 <> 0
let is_psh fs = fs land 0x08 <> 0
let is_ack fs = fs land 0x10 <> 0
let is_urg fs = fs land 0x20 <> 0

let flags_to_string flags = 
  sprintf "%s%s%s%s%s%s"
    (if (is_fin flags) then "F" else ".")
    (if (is_syn flags) then "S" else ".")
    (if (is_rst flags) then "R" else ".")
    (if (is_psh flags) then "P" else ".")
    (if (is_ack flags) then "A" else ".")
    (if (is_urg flags) then "U" else ".")  

let to_str buf = 
  sprintf "%d,%d,%s"
    (get_tcp4_srcpt buf) (get_tcp4_dstpt buf)
    (get_tcp4_flags buf |> flags_to_string)

let to_string buf =
  sprintf "src:%d dst:%d seq:%lu ack:%lu offset:%d flags:%s win:%d xsum:%04x urg:%d"
    (get_tcp4_srcpt buf) (get_tcp4_dstpt buf)
    (get_tcp4_seqno buf) (get_tcp4_ackno buf)
    (get_tcp4_offset buf) (get_tcp4_flags buf |> flags_to_string)
    (get_tcp4_window buf) (get_tcp4_xsum buf) (get_tcp4_urgent buf)
