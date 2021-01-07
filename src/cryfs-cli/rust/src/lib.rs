#[cxx::bridge]
mod ffi {
  extern "Rust" {
    fn hello_from_rust() -> &'static str;
  }

  unsafe extern "C++" {
    include!("cryfs-cli/Cli.h");
    fn hello_from_cpp();
  }
}

fn hello_from_rust() -> &'static str {
  ffi::hello_from_cpp();
  "Hello from Rust"
}

mod lib2;
