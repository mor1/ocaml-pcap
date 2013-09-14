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

let print_packet p =
  printf "ETH(%s)|" (Ethernet.to_string p);
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
        | Some proto -> printf "unknown ip proto %d\n" (Ip.protocol_to_int proto)
        | None -> printf "parse error\n"
    )
    | _ -> printf "unknown ethertype\n"
    
let rec print_pcap_packet h (hdr,pkt) =
  let module H = (val h: HDR) in
  let open H in
  printf "\n** %lu.%lu  bytes %lu (of %lu)\n" 
    (get_pcap_packet_ts_sec hdr)
    (get_pcap_packet_ts_usec hdr)
    (get_pcap_packet_incl_len hdr)
    (get_pcap_packet_orig_len hdr);
  print_packet pkt
  
let print_pcap_header h buf =
  let module H = (val h: HDR) in
  let open H in
  printf "pcap_header (len %d)\n" sizeof_pcap_header;
  printf "endian: %s\n" (string_of_endian H.endian);
  printf "version %d %d\n" 
   (get_pcap_header_version_major buf) (get_pcap_header_version_minor buf);
  printf "timezone shift %lu\n" (get_pcap_header_thiszone buf);
  printf "timestamp accuracy %lu\n" (get_pcap_header_sigfigs buf);
  printf "snaplen %lu\n" (get_pcap_header_snaplen buf);
  printf "lltype %lx\n" (get_pcap_header_network buf)

let parse filename =
  printf "filename: %s\n" filename;
  let fd = Unix.(openfile filename [O_RDONLY] 0) in
  let buf = Bigarray.(Array1.map_file fd Bigarray.char c_layout false (-1)) in
  let buf = Cstruct.of_bigarray buf in
  printf "total pcap file length %d\n" (Cstruct.len buf);

  let header, body = Cstruct.split buf sizeof_pcap_header in
  match Pcap.detect header with
  | Some h ->
    print_pcap_header h header;

    let packets = Pcap.packets h body in

    let num_packets = Cstruct.fold
      (fun a packet -> print_pcap_packet h packet; (a+1)) 
      packets 0
    in
    printf "num_packets %d\n" num_packets
  | None ->
    Printf.fprintf stderr "not a pcap file (failed to read magic number in header)\n%!"

let _ =
  let files = ref [] in
  Arg.parse []
    (fun x -> files := x :: !files)
    "Dump the contents of pcap files";
  let files = List.rev !files in
  List.iter parse files
