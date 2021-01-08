#[cxx::bridge]
mod ffi {
  extern "Rust" {
    fn hello_from_rust_3() -> &'static str;
  }
}

fn hello_from_rust_3() -> &'static str {
  "Hello from Rust"
}
