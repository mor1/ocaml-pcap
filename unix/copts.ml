open Cmdliner
  
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
