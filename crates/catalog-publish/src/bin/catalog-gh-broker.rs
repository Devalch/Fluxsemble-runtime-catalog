#[allow(dead_code)]
#[path = "../broker.rs"]
mod broker;

fn main() {
    if broker::run_process().is_err() {
        broker::fail_process();
    }
}
