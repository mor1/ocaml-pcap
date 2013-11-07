open Lwt

let get = function Some x -> x | None -> failwith "Bad IP!"
let ip = `IPv4 (
  get (Ipaddr.V4.of_string "10.0.0.2"),
  get (Ipaddr.V4.of_string "255.255.255.0"),
  [get (Ipaddr.V4.of_string "10.0.0.1")]
)

let listen_port = 80
let listen_address = None

let main _ _ _ =
      Printf.eprintf "Y\n%!";
  Net.Manager.create (fun mgr interface id ->
      Printf.eprintf "X\n%!";
      OS.Console.log "creating interface";
      Net.Manager.configure interface ip >>
      OS.Time.sleep 5.0 >>
      return ()
    )
