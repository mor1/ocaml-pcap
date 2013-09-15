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
  
open Printf
  
let buf_to_string pfx buf = 
  let line_len = 16 in
  
  let line bs = 
    let line = ref "" in
    for i = 0 to (min line_len (Cstruct.len bs)) - 1do
      if i > 0 && i mod 8 == 0 then line := !line ^ " ";
      line := sprintf "%s%02x." !line (Cstruct.get_uint8 bs i)
    done;
    !line
  in
  
  let rec fold f acc = function
    | buf when Cstruct.len buf < line_len -> 
      sprintf "%s\n%s%s" acc pfx (line buf)
    | buf -> 
      fold f (f acc buf) (Cstruct.shift buf line_len)
  in
  
  fold 
    (fun a v -> sprintf "%s\n%s%s" a pfx (line v))
    ""
    buf

type t = 
  | ETH  of Ethernet.h * t
  | IP4 of Ip4.h * t
  | TCP4  of Tcp4.h * t
  | UDP4  of Udp4.h * t
      
  | DHCP of Dhcp.t

  | DATA of Cstruct.t
  | ERROR of Cstruct.t

let to_str pkt =
  let rec aux pkt str =  
    match pkt with
      | ETH (h, p) -> 
        let s = sprintf "%s|ETH(%s)" str (Ethernet.to_str h) in aux p s
      | IP4 (h, p)   -> 
        let s = sprintf "%s|IP4(%s)" str (Ip4.to_str h) in aux p s
      | TCP4 (h, p)  -> 
        let s = sprintf "%s|TCP4(%s)" str (Tcp4.to_str h) in aux p s
      | UDP4 (h, p)  -> 
        let s = sprintf "%s|UDP4(%s)" str (Udp4.to_str h) in aux p s

      | DHCP p -> sprintf "%s|%s" str (Dhcp.to_str p)

      | DATA bs -> sprintf "%s|DATA(%s)" str (buf_to_string "\t" bs)
      | ERROR bs -> sprintf "%s|ERR(%s)" str (buf_to_string "\t" bs)
  in
  aux pkt ""

let to_string pkt =
  let rec aux pkt str =  
    match pkt with
      | ETH (h, p) -> 
        let s = sprintf "%s|ETH(%s)" str (Ethernet.to_string h) in aux p s
      | IP4 (h, p)   -> 
        let s = sprintf "%s|IP4(%s)" str (Ip4.to_string h) in aux p s
      | TCP4 (h, p)  -> 
        let s = sprintf "%s|TCP4(%s)" str (Tcp4.to_string h) in aux p s
      | UDP4 (h, p)  -> 
        let s = sprintf "%s|UDP4(%s)" str (Udp4.to_string h) in aux p s

      | DHCP p -> sprintf "%s|%s" str (Dhcp.to_string p)

      | DATA bs -> sprintf "%s|DATA(%s)" str (buf_to_string "\t" bs)
      | ERROR bs -> sprintf "%s|ERR(%s)" str (buf_to_string "\t" bs)
  in
  aux pkt ""
 
