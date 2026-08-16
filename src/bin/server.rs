#![allow(
    dead_code,
    unused_variables,
    unused_assignments,
    non_camel_case_types,
    clippy::upper_case_acronyms
)]

use tcup::{error::Result, tcup::TCup};

#[tokio::main]
async fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().collect();

    tracing_subscriber::fmt()
        .with_target(false)
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let if_name = "tcup";
    let if_addr = "10.0.0.1/24";
    let port = 1337;

    let tcup = TCup::init(if_name, if_addr)?;

    tcup.run().await;
    println!("shuttting down");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_tcup() {
        let if_name = "tcup";
        let if_addr = "10.0.0.1/24";
        let port = 1337;
        let tcup = TCup::init(if_name, if_addr).unwrap();

        tokio::spawn(async move {
            tcup.run().await;
        });
    }

    #[tokio::test]
    async fn test_name() -> Result<()> {
        init_tcup();
        Ok(())
    }
}
