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
open Pcap
open Printf

type st = {
  mutable nflows: int;
}
let st = {
  nflows = 0
}

let flow_demux st buf = 
  let shallow_tcp4_port_demux st th =
    st.nflows <- st.nflows + 1;
    (fun _ -> Packet.DROP)
  in
  let shallow_ipproto_demux st ih = 
    let open Ip4 in
    match int_to_protocol ih.proto with
      | Some t -> (match t with
          | UDP -> Demux.drop_demux
          | TCP -> Demux.tcp4_demux st shallow_tcp4_port_demux
          | _ -> Demux.drop_demux
      )
      | None -> Demux.drop_demux
  in
  let shallow_ethertype_demux st eh = 
    let open Ethernet in
    match int_to_ethertype eh.ethertype with
      | Some t -> (match t with
          | IP4 -> Demux.ip_demux st shallow_ipproto_demux
          | _ -> Demux.drop_demux
      )
      | None -> Demux.drop_demux
  in
  Demux.eth_demux st shallow_ethertype_demux buf

let buf filename = 
  printf "filename: %s\n" filename;
  let fd = Unix.(openfile filename [O_RDONLY] 0) in
  let buf = Bigarray.(Array1.map_file fd Bigarray.char c_layout false (-1)) in
  let buf = Cstruct.of_bigarray buf in
  printf "total pcap file length %d\n" (Cstruct.len buf);
  buf

let parse buf =
  match Pcap.iter buf (flow_demux st) with
    | None -> 
      fprintf stderr "not a pcap file (failed to read magic number in header)\n%!"
    
    | Some (pcap_header, pcap_packets) -> 
      let open Pcap in
      printf "### %s\n%!" (fh_to_string pcap_header);
      let num_packets = Cstruct.fold
        (fun a (PCAP(h, p)) -> 
          printf "%d: %s\n\t%s\n%!" a (to_string h) (Packet.to_str p); (a+1))
        pcap_packets 0
      in
      printf "num_packets %d\n" num_packets;
      printf "num_flows %d\n%!" st.nflows

let _ =
  let files = ref [] in
  Arg.parse []
    (fun x -> files := x :: !files)
    "Dump the contents of pcap files";
  let files = List.rev !files in
  List.iter (fun file -> file |> buf |> parse) files
