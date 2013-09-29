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

open Capture
open Capture.Pcap
open Capture.Packet

let write fd buf = 
  let s = Cstruct.to_string buf in
  Unix.write fd s 0 (String.length s)

let create_pcap filename fh = 
  let buf = Cstruct.create Pcap.sizeof_pcap_header in
  let open Pcap.LE in
  set_pcap_header_magic_number buf fh.magic_number;
  set_pcap_header_version_major buf fh.version_major;
  set_pcap_header_version_minor buf fh.version_minor;
  set_pcap_header_thiszone buf fh.timezone;
  set_pcap_header_sigfigs buf fh.sigfigs;
  set_pcap_header_snaplen buf fh.snaplen;
  set_pcap_header_network buf fh.network;

  try 
    let fd = Unix.(openfile filename [O_WRONLY; O_CREAT; O_TRUNC] 0o644) in
    let _ = write fd buf in
    fd
  with
    | Unix.Unix_error (errno, func, param) ->
      printf "%s %s %s\n%!" (Unix.error_message errno) func param;
      failwith "DIE!"
    

module Unidir = struct

  type t = (int32 * int * int32 * int)
    
  let compare x y = compare x y

  let t ih th = 
    (ih.Ip4.src, th.Tcp4.srcpt, ih.Ip4.dst, th.Tcp4.dstpt)

  let to_string (tx, txpt, rx, rxpt) =
    sprintf "%s/%d -> %s/%d"
      (Ip4.ip_to_string tx) txpt (Ip4.ip_to_string rx) rxpt

end

module Bidir = struct

  type t = (int32 * int * int32 * int)
  type dir = OUT | BACK
  type f = t * dir
  
  let compare x y = compare x y
  
  let f ih th = 
    let (tx, txpt, rx, rxpt) = 
      (ih.Ip4.src, th.Tcp4.srcpt, ih.Ip4.dst, th.Tcp4.dstpt)
    in
    if (tx < rx) || (tx == rx && txpt <= rxpt) then 
      (tx, txpt, rx, rxpt, OUT) 
    else
      (rx, rxpt, tx, txpt, BACK)

  let t ih th =
    let (tx, txpt, rx, rxpt, _) = f ih th in
    (tx, txpt, rx, rxpt)

  let to_string (tx, txpt, rx, rxpt) =
    sprintf "%s/%d -> %s/%d"
      (Ip4.ip_to_string tx) txpt (Ip4.ip_to_string rx) rxpt

  let f_to_string (tx, txpt, rx, rxpt, dir) =
    let tx, txpt, rx, rxpt = match dir with
        | OUT -> ((Ip4.ip_to_string tx), txpt, (Ip4.ip_to_string rx), rxpt)
        | BACK -> ((Ip4.ip_to_string rx), rxpt, (Ip4.ip_to_string tx), txpt)
    in
    sprintf "%s/%d -> %s/%d" tx txpt rx rxpt
end

module UniFlows = Map.Make(Unidir)  
module BiFlows = Map.Make(Bidir)


let flow_to_filename (src, srcpt, dst, dstpt, dir) = 
  let open Bidir in
  let src, srcpt, dst, dstpt = match dir with
    | OUT -> src, srcpt, dst, dstpt
    | BACK -> dst, dstpt, src, srcpt
  in  
  sprintf "x-%s.%d-%s.%d.pcap" (Ip4.ip_to_string src) srcpt (Ip4.ip_to_string dst) dstpt

module Flowstate = struct
  type t = {
    mutable npkts: int;
    fd: Unix.file_descr;
    mutable pbuf: Capture.Packet.t list;
  }

  let to_string t = 
    sprintf "npkts:%d" t.npkts

  let create f fh = 
    { npkts = 0;
      fd = create_pcap (flow_to_filename f) fh;
      pbuf = [];
    }
    
end

module State = struct
  type t = {
    mutable npkts: int;
    mutable nflows: int;
    mutable fh: Pcap.fh option;
    mutable biflows: Flowstate.t BiFlows.t;
  }

  let create () = {
    npkts = 0;
    nflows = 0;
    fh = None;
    biflows = BiFlows.empty;
  }

  let to_string t = 
    let hdr = sprintf "npkts: %d\nnflows: %d\n" t.npkts t.nflows in
    BiFlows.fold
      (fun f fst acc -> 
        sprintf "%s%s: %s\n" acc (Bidir.to_string f) (Flowstate.to_string fst)
      ) 
      t.biflows hdr
      
  let dump t = 
    printf "npkts: %d\nnflows: %d\n" t.npkts t.nflows;
    BiFlows.iter
      (fun f fst -> 
        printf "%s: %s\n" (Bidir.to_string f) (Flowstate.to_string fst)
      ) 
      t.biflows 
end


(** how to process each packet *)
let pkt_process st pkt =
  let open State in
  if st.npkts mod 1_000_000 == 0 then
    printf "npkts=%d nflows=%d\n%!" st.npkts st.nflows;

  st.npkts <- st.npkts + 1;
  (match pkt with
    | PCAP(h, ETH(eh, IP4(ih, TCP4(th, _))), buf) ->
      let t = Bidir.t ih th in
      let f = Bidir.f ih th in
      let fst = 
        try
          BiFlows.find t st.biflows
        with Not_found -> 
          st.nflows <- st.nflows + 1;
          match st.fh with 
            | None -> failwith "argh"
            | Some fh -> Flowstate.create f fh
      in
      Flowstate.(fst.npkts <- fst.npkts + 1);
      let _ = write fst.Flowstate.fd buf in
      st.biflows <- BiFlows.add t fst st.biflows
    | _ -> ()
  );
  st

(** parse a buffer, with state *)
let parse st buf =
  
  (** customise protocol demux to be as shallow as we can: ETH -> IP -> TCP ->
      DROP; not strictly necessary as it's hardly likely that doing a full demux
      (per Demux.eth_demux) is a bottleneck given how few protocols are
      implemented, but an excuse to test in principle *)
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
  in

  (* actually proces the buffer, folding over the packets it contains *)
  match Pcap.iter buf (flow_demux st) with
    | None -> 
      fprintf stderr "not a pcap file (failed to read magic number in header)\n%!"
        
    | Some (header, packets) -> 
      let open Pcap in
      printf "### %s\n%!" (fh_to_string header);
      st.State.fh <- Some header;
      let _ = Cstruct.fold pkt_process packets st in
      printf "npkts: %d\n" st.State.npkts;
      printf "nflows: %d == %d\n%!" st.State.nflows (BiFlows.cardinal st.State.biflows)

(** convert [filename] string to a buffer by opening and mapping file *)
let filename_to_buf filename = 
  let fd = Unix.(openfile filename [O_RDONLY] 0) in
  let buf = Bigarray.(Array1.map_file fd Bigarray.char c_layout false (-1)) in
  let buf = Cstruct.of_bigarray buf in
  buf

