fn main() {
    if std::env::args_os().len() != 1 {
        eprintln!("OMNIS_CHECKPOINTD_ZERO_ARGUMENTS_REQUIRED");
        std::process::exit(2);
    }
    if let Err(error) = jcode_omnis::daemon::run_production() {
        eprintln!("OMNIS_CHECKPOINTD_REFUSED: {error:#}");
        std::process::exit(1);
    }
}
