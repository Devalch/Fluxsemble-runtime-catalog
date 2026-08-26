use catalog_core::production_key_identity;

fn main() {
    let _compiled_identity = production_key_identity();
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match catalog_sign::run_cli(&arguments) {
        Ok(summary) => println!("{summary}"),
        Err(_) => {
            eprintln!("catalog signing failed");
            std::process::exit(1);
        }
    }
}
