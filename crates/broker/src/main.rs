fn main() {
    if let Err(e) = vasp_broker::run() {
        eprintln!("VASP broker: {e:#}");
        std::process::exit(1);
    }
}
