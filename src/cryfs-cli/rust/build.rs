fn main() {
    let _build = cxx_build::bridges(vec!["src/lib.rs", "src/lib2.rs"].into_iter());

    println!("cargo:rerun-if-changed=src/lib.rs");
    println!("cargo:rerun-if-changed=src/lib2.rs");
}
