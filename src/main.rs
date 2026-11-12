//! wren-vault: the program. It serves the pipe protocol on its standard input and output (README.md) and exits when
//! the input closes or after `lock`. It writes nothing else on standard output.

fn main() {
    wren_vault::harden::apply();
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    {
        Ok(r) => r,
        Err(_) => {
            eprintln!("wren-vault: cannot start");
            std::process::exit(70);
        }
    };
    let code = match runtime.block_on(wren_vault::server::serve(tokio::io::stdin(), tokio::io::stdout())) {
        Ok(()) => 0,
        Err(_) => 74,
    };
    // (exit at once: a read of stdin may still wait on a blocking thread, and the runtime's drop would wait for it)
    std::process::exit(code);
}
