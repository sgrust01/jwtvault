use std::process::Command;

fn main() {
    let store = "store";
    let _ = if cfg!(target_os = "linux") {
        Command::new("sh")
            .arg("generate_certificates.sh")
            .arg(store)
            .output()
            .expect("failed to execute process");
    }
    else {
        Command::new("cmd")
            .args(&["./generate_certificates.sh", store])
            .output()
            .expect("failed to execute process");
    };
}