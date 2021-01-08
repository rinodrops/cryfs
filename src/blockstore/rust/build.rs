fn main() {
    let _build = cxx_build::bridges(vec!["src/lib.rs"].into_iter());

    println!("cargo:rerun-if-changed=src/lib.rs");
}
