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
open Packet

type st = {
  mutable nflows: int;
}
let st = {
  nflows = 0
}

let flow ih th = (ih.Ip4.src, ih.Ip4.dst, th.Tcp4.srcpt, th.Tcp4.dstpt)
let flow_to_str (srcip, dstip, srcpt, dstpt) = 
  sprintf "%s/%d -> %s/%d"
    (Ip4.ip_to_string srcip) srcpt (Ip4.ip_to_string dstip) dstpt

(* filter and process only TCP/IP packets *)
let process acc = function
  | PCAP(h, ETH(eh, IP4(ih, TCP4(th, _)))) ->
    let f = flow ih th in
    printf "%d: %s\n%!" st.nflows (flow_to_str f);
    st.nflows <- st.nflows + 1;
    acc+1
  | _ -> acc+1

(* customise protocol demux to be as shallow as we can: ETH -> IP -> TCP -> DROP *)
let flow_demux st buf = 
  let shallow_ipproto_demux st ih = 
    let open Ip4 in
    match int_to_protocol ih.proto with
      | Some t -> (match t with
          | TCP -> Demux.tcp4_demux st (fun st th -> Demux.drop_demux)
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

let filename_to_buf filename = 
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
      let num_packets = Cstruct.fold process pcap_packets 0 in
      printf "num_packets %d\n" num_packets;
      printf "num_flows %d\n%!" st.nflows

let _ =
  let files = ref [] in
  Arg.parse []
    (fun x -> files := x :: !files)
    "Dump the contents of pcap files";
  let files = List.rev !files in
  List.iter (fun file -> file |> filename_to_buf |> parse) files
