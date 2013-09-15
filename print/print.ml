(*
 * Copyright (c) 2012 Anil Madhavapeddy <anil@recoil.org>
 *           (c) 2012 Citrix Systems
 *           (c) 2013 Richard Mortier <mort@cantab.net>
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

(* Simple pcap printer which understands TCP/IP and ethernet *)

open Operators
open Pcap
open Printf

(*
let print_packet p =
  printf "ETH(%s)|" (Ethernet.to_str p);
  let ethertype = Ethernet.(get_ethernet_ethertype p |> int_to_ethertype) in
  match ethertype with
    | Some Ethernet.IP4 -> (
      let ip = Cstruct.shift p Ethernet.sizeof_ethernet in
      printf "IP4(%s)|" (Ip.to_string ip);
      let proto = Ip.(get_ip4_proto ip |> int_to_protocol) in
      match proto with 
        | Some Ip.TCP -> (
          let tcp = Cstruct.shift ip Ip.sizeof_ip4 in
          let offset = Tcp.get_tcp4_offset tcp in
          let payload = Cstruct.shift tcp offset in
          printf "TCP4(%s)|" (Tcp.to_string tcp);
          printf "%S\n" (Cstruct.to_string payload)
        )
        | Some Ip.UDP -> (
          let udp = Udp.h ip in
          printf "UDP4(%s)|" (Udp.h_to_string udp)
        )
        | Some proto -> printf "unknown ip proto %d\n" (Ip.protocol_to_int proto)
        | None -> printf "parse error\n"
    )
    | _ -> printf "unknown ethertype\n"
    
*)

let parse filename =
  printf "filename: %s\n" filename;
  let fd = Unix.(openfile filename [O_RDONLY] 0) in
  let buf = Bigarray.(Array1.map_file fd Bigarray.char c_layout false (-1)) in
  let buf = Cstruct.of_bigarray buf in
  printf "total pcap file length %d\n" (Cstruct.len buf);

  let demuxf st buf = Packet.DATA(buf) in
  match Pcap.iter buf (demuxf ()) with
    | None -> 
      fprintf stderr "not a pcap file (failed to read magic number in header)\n%!"
    | Some (pcap_header, pcap_packets) -> 
      let open Pcap in
      printf "### %s\n%!" (fh_to_string pcap_header);
      let num_packets = Cstruct.fold
        (fun a (PCAP(h, p)) -> 
          printf "%d: %s\n\t%s\n%!" a (to_string h) (Packet.to_string p); (a+1))
        pcap_packets 0
      in
      printf "num_packets %d\n" num_packets

let _ =
  let files = ref [] in
  Arg.parse []
    (fun x -> files := x :: !files)
    "Dump the contents of pcap files";
  let files = List.rev !files in
  List.iter parse files
