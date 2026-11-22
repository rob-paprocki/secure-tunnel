fn main() {
    // The shared desktop files leave out desktop-only code under this flag.
    println!("cargo:rustc-cfg=st_mobile");
}
