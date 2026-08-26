use catalog_core::production_key_identity;

fn main() {
    let isolation = match catalog_sign::enter_signer_isolation() {
        Ok(isolation) => isolation,
        Err(_) => fail(),
    };
    let _compiled_identity = production_key_identity();
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match catalog_sign::run_isolated_cli(&isolation, &arguments).and_then(|summary| {
        catalog_sign::emit_reverse_transfer_manifest(&isolation)?;
        Ok(summary)
    }) {
        Ok(summary) => println!("{summary}"),
        Err(_) => fail(),
    }
}

fn fail() -> ! {
    eprintln!("catalog signing failed");
    std::process::exit(1);
}
