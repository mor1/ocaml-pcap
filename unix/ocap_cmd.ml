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

open Cmdliner;;
open Ocap;;

let version = "0.1+" ^ Ocap.version

let str = Printf.sprintf

let pr = Printf.printf

(* common options, following Cmdliner documentation *)
type verbosity = Quiet | Normal | Verbose
let verbosity_to_string = function
  | Quiet -> "quiet"
  | Normal -> "normal"
  | Verbose -> "verbose"

type copts = {
  verbosity: verbosity;
  debug: bool;
  no_progress: bool;
}

let copts verbosity debug no_progress = { verbosity; debug; no_progress }

module Commands = struct

  let print copts =
    pr "verbosity = %s\ndebug = %b\nno_progress = %b\n"
      (verbosity_to_string copts.verbosity) copts.debug copts.no_progress

  let reform copts =
    pr "verbosity = %s\ndebug = %b\nno_progress = %b\n"
      (verbosity_to_string copts.verbosity) copts.debug copts.no_progress

  let statistics copts =
    pr "verbosity = %s\ndebug = %b\nno_progress = %b\n"
      (verbosity_to_string copts.verbosity) copts.debug copts.no_progress

  let help copts man_format cmds topic = match topic with
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

end

let copts_sect = "COMMON OPTIONS"

let copts_t =
  let docs = copts_sect in
  let debug =
    let doc = "Include debug output." in
    Arg.(value & flag & info ["debug"] ~docs ~doc)
  in
  let verbose =
    let doc = "Suppress output." in
    let quiet = Quiet, Arg.info ["q"; "quiet"] ~docs ~doc in
    let doc = "Verbose output." in
    let verbose = Verbose, Arg.info ["v"; "verbose"] ~docs ~doc in
    Arg.(last & vflag_all [Normal] [quiet; verbose])
  in
  let no_progress =
    let doc = "Turn off progress indication." in
    Arg.(value & flag & info ["no-progress"] ~docs ~doc)
  in
  Term.(pure copts $ verbose $ debug $ no_progress)


let help_sects = [
  `S copts_sect;
  `P "These options are common to all commands.";
  `S "MORE HELP";
  `P " `$(mname) $(i,COMMAND) --help' for help on a single command."; `Noblank;
  `P " `$(mname) help print' for help on displaying captures."; `Noblank;
  `P " `$(mname) help reform' for help on displaying captures."; `Noblank;
  `P " `$(mname) help statistics' for help on capture file statistics.";
  `S "BUGS"; `P "Check bug reports at http://github.com/mor1/ocap/issues/.";
]

let print_t =
  let doc = "render a capture file to stdout" in
  let man =
    [`S "DESCRIPTION";
     `P "Renders a capture file to stdout. ..."] @ help_sects
  in
  Term.(pure Commands.print $ copts_t),
  Term.info "print" ~doc ~sdocs:copts_sect ~man

let reform_t =
  let doc = "split/merge capture files" in
  let man =
    [`S "DESCRIPTION";
     `P "Split or merge capture files. ..."] @ help_sects
  in
  Term.(pure Commands.reform $ copts_t),
  Term.info "reform" ~doc ~sdocs:copts_sect ~man

let statistics_t =
  let doc = "render capture file statistics" in
  let man =
    [`S "DESCRIPTION";
     `P "Renders statistics about a capture file. ..."] @ help_sects
  in
  Term.(pure Commands.statistics $ copts_t),
  Term.info "statistics" ~doc ~sdocs:copts_sect ~man

let help_t =
  let topic =
    let doc = "The topic to get help on. `topics' lists the topics." in
    Arg.(value & pos 0 (some string) None & info [] ~docv:"TOPIC" ~doc)
  in
  let doc = "display help about ocap commands and common options" in
  let man =
    [`S "DESCRIPTION";
     `P "Prints help about ocap commands and common options..."] @ help_sects
  in
  Term.(ret (pure Commands.help
             $ copts_t $ Term.man_format $ Term.choice_names $ topic)),
  Term.info "help" ~doc ~man

let default_cmd =
  let doc = "capture file manipulation" in
  let man = help_sects in
  Term.(ret (pure (fun _ -> `Help (`Pager, None)) $ copts_t)),
  Term.info "ocap" ~version:version ~sdocs:copts_sect ~doc ~man

let cmds = [ print_t; reform_t; statistics_t; help_t ]

let () =
  match Term.eval_choice default_cmd cmds with
  | `Error _ -> exit 1
  | _ -> exit 0
