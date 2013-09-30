(*
 * Copyright (c) 2013 Richard Mortier <mort@cantab.net>
 * and Richard G. Clegg <richard@richardclegg.org>
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

open Capture
open Capture.Pcap
open Capture.Packet

open Printf
open Flowlib


type var_int = int  (* Improve for more compact representation*)



module Packedflow = struct
    type pflow_pkt = {
        time_delta: var_int;
        ack_delta: var_int;
        seq_delta: var_int;
        length: int;
        flags: int;
    }

    type t = {
        mutable header: Pcap.fh option;
        mutable pkts: pflow_pkt list;
        mutable timenow: int;  (*Time of last packet*)
        mutable acknow: int;   (*last ack no*)
        mutable seqnow: int;   (*last seq no*)
        mutable totpkts: int;  (* Num packets*)
        mutable totbytes: int;   (* Num bytes *)
        mutable tottime: int;   (* Total time taken *)
    }
    
    let create () = {
        header= None;
        pkts= [];
        totpkts= 0;
        totbytes= 0;
        tottime= 0;
        seqnow= 0;
        acknow= 0;
        timenow= 0
    }
    
    let addPkt pflow fhe = 
        pflow.totpkts <-pflow.totpkts+1;
        match pflow.header with 
            | None -> pflow.header <- fhe;
            | _ -> pflow.tottime<-pflow.tottime+1;
            
end


(** entry point *)
let _ =

  let st = Flowlib.State.create () in
  let files = ref [] in
  Arg.parse []
    (fun x -> files := x :: !files)
    "Dump the contents of pcap files";

  let files = List.rev !files in
    List.iter (fun file -> file |> Flowlib.filename_to_buf |> Flowlib.parse st pkt_process_summary_flow) files;

  State.dump st

  
