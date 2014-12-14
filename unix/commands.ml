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

let print copts =
  let pr, vpr = pr copts, vpr copts in
  vpr "verbosity = %s\ndebug = %b\nno_progress = %b\n"
    (verbosity_to_string copts.verbosity) copts.debug copts.no_progress;
  pr "HELLO\n%!"

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
