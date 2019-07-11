(*
open Devkit
open ExtLib
open Printf
*)

module Passwords = Pwned_passwords.Make(Pwned_passwords.Lwt)

open Cmdliner

let () =
  let with_passwords filename f =
    let storage_filename = filename ^ ".idx" in
    let module Storage : Pwned_passwords.Storage with type 'a io = 'a Lwt.t =
      struct
        type 'a io = 'a Lwt.t
        let read () =
          match%lwt Lwt_unix.file_exists storage_filename with
          | false -> Lwt.return_none
          | true ->
          Lwt_io.with_file ~mode:Input storage_filename @@ fun ch ->
          let%lwt s = Lwt_io.read ch in
          Lwt.return_some s
        let write s =
          (* TODO use temp file and rename for atomicity *)
          Lwt_io.with_file ~mode:Output ~perm:0o660 storage_filename @@ fun ch ->
          Lwt_io.write ch s
      end
    in
    let module Passwords = Passwords(Storage) in
    let%lwt pw = Passwords.init filename in
    let%lwt () = f Passwords.prefix_size (Passwords.lookup pw) in
    let%lwt () = Passwords.shutdown pw in
    Lwt.return_unit
  in
  let filename =
    let doc = "passwords database file" in
    Arg.(required & pos 0 (some string) None & info [] ~docv:"FILE" ~doc)
  in
  let init =
    let init filename =
      Lwt_main.run @@
      with_passwords filename @@ fun _prefix_size _lookup ->
      Lwt.return_unit
    in
    let open Term in
    const init $ filename,
    let doc = "initailize database indices" in
    let exits = default_exits in
    let man = [] in
    info "init" ~doc ~sdocs:Manpage.s_common_options ~exits ~man
  in
  let lookup =
    let lookup filename =
      Lwt_main.run @@
      with_passwords filename @@ fun prefix_size lookup ->
      Lwt_io.read_lines Lwt_io.stdin |>
      Lwt_stream.iter_s @@ function
      | prefix when String.length prefix < prefix_size -> Lwt.return_unit
      | prefix ->
      let%lwt hashes = lookup prefix in
      Lwt_list.iter_s Lwt_io.printl hashes
    in
    let open Term in
    const lookup $ filename,
    let doc = "lookup password hashes interactively" in
    let exits = default_exits in
    let man = [] in
    info "lookup" ~doc ~sdocs:Manpage.s_common_options ~exits ~man
  in
  Term.(exit (eval_choice init [ lookup; ]))
