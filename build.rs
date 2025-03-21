fn main() {
    #[cfg(not(target_family = "windows"))]
    panic!("Support only windows");
    
    #[cfg(target_arch = "x86_64")]
    println!("cargo::rustc-link-search=WinDivert/x64");
    #[cfg(target_arch = "x86")]
    println!("cargo::rustc-link-search=WinDivert/x86");
}
