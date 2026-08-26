use catalog_sign::{SignError, emit_reverse_transfer_manifest, enter_signer_isolation};

fn main() {
    let isolation = match enter_signer_isolation() {
        Ok(isolation) => isolation,
        Err(_) => fail(),
    };
    let arguments = std::env::args().skip(1).collect::<Vec<_>>();
    match catalog_sign::run_fixture_isolated_cli(&isolation, &arguments).and_then(|summary| {
        emit_reverse_transfer_manifest(&isolation)?;
        Ok(summary)
    }) {
        Ok(summary) => println!("{summary}"),
        Err(SignError::OutputDurabilityUncertain) => {
            let _ = catalog_sign::recover_fixture_isolated_output(&isolation)
                .and_then(|_| emit_reverse_transfer_manifest(&isolation));
            fail()
        }
        Err(_) => fail(),
    }
}

fn fail() -> ! {
    eprintln!("catalog fixture signing failed");
    std::process::exit(1);
}
