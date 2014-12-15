(*
 * Copyright (c) 2014 Richard Mortier <mort@cantab.net>
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

open Lwt
open Copts

(* conditional printers, conditioned on copts *)
let pr copts = match copts.verbosity with
  | Quiet -> Printf.ifprintf stderr
  | Normal -> Printf.fprintf stderr
  | Verbose -> Printf.fprintf stderr
let vpr copts = match copts.verbosity with
  | Quiet -> Printf.ifprintf stderr
  | Normal -> Printf.ifprintf stderr
  | Verbose -> Printf.fprintf stderr

let print copts filenames =
  let pr, vpr = pr copts, vpr copts in
  vpr "verbosity = %s\ndebug = %b\nno_progress = %b\n"
    (verbosity_to_string copts.verbosity) copts.debug copts.no_progress;

  pr "HELLO\n%!";
  (* XXX how to stop type inference deciding that `pr` must have only one *)
  (* parameter above? *)

  let open Printf in
  let files = List.map Seq.of_filename filenames in
  List.iter (fun (file, (fileheader,packets)) ->
      printf "\
        ### START: filename:%s size:%d\n\
        %s\n%!" file.Seq.filename file.Seq.filesize (Pcap.fh_to_str fileheader);
      let npackets =
        Cstruct.fold (fun acc pkt ->
          let Pcap.PCAP(h, p, _) = pkt in
          printf "%d: PCAP(%s)%s\n%!" acc (Pcap.to_str h) (Packet.to_str p);
          acc+1
          ) packets 0
      in
      printf "### END: npackets:%d\n%!" npackets
    ) files;

  pr "GOODBYE\n%!"

let reform copts =
  let pr, vpr = pr copts, vpr copts in
  pr "verbosity = %s\ndebug = %b\nno_progress = %b\n"
    (verbosity_to_string copts.verbosity) copts.debug copts.no_progress

let statistics copts =
  let pr, vpr = pr copts, vpr copts in
  pr "verbosity = %s\ndebug = %b\nno_progress = %b\n"
    (verbosity_to_string copts.verbosity) copts.debug copts.no_progress

let help copts man_format cmds topic =
  let pr, vpr = pr copts, vpr copts in
  match topic with
  | None -> `Help (`Pager, None)
  | Some topic ->
    let topics = "topics" :: "patterns" :: "environment" :: cmds in
    let conv, _ = Cmdliner.Arg.enum (List.rev_map (fun s -> (s, s)) topics) in
    match conv topic with
    | `Error e -> `Error (false, e)
    | `Ok t when t = "topics" -> List.iter print_endline topics; `Ok ()
    | `Ok t when List.mem t cmds -> `Help (man_format, Some t)
    | `Ok t ->
      let page = (topic, 7, "", "", ""), [`S topic; `P "Say something";] in
      `Ok (Cmdliner.Manpage.print man_format Format.std_formatter page)
