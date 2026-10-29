use std::process::Command;

fn run(args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_rivemu-lockstep"))
        .args(args)
        .output()
        .expect("run rivemu-lockstep")
}

#[test]
fn rejects_invalid_or_missing_option_values() {
    for (args, expected) in [
        (
            &["risu", "--seed", "garbage"][..],
            "invalid value for --seed",
        ),
        (
            &["risu", "--blocks", "nope"][..],
            "invalid value for --blocks",
        ),
        (&["risu", "--qemu"][..], "--qemu requires a value"),
        (&["boot", "--bios"][..], "--bios requires a value"),
    ] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(2));
        assert!(
            String::from_utf8_lossy(&output.stderr).contains(expected),
            "stderr was: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}

#[test]
fn rejects_zero_work_counts() {
    for args in [
        &["risu", "--blocks", "0"][..],
        &["risu", "--insns", "0"][..],
        &["boot", "--steps", "0"][..],
    ] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("must be greater than zero"));
    }
}
