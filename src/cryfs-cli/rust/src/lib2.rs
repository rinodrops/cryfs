#[cxx::bridge]
mod ffi {
    extern "Rust" {
        fn hello_from_rust_2() -> &'static str;
    }

    unsafe extern "C++" {
        include!("cryfs-cli/Cli.h");
        fn hello_from_cpp_2();
    }
}

fn hello_from_rust_2() -> &'static str {
    ffi::hello_from_cpp_2();
    "Hello from Rust 2"
}
