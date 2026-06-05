#![cfg_attr(all(feature = "sp1", not(test)), no_main)]

#[cfg(any(feature = "nitro", feature = "sp1"))]
mod blob;

#[cfg(any(feature = "nitro", feature = "sp1"))]
mod dpos_committee;

#[cfg(feature = "nitro")]
pub mod nitro;

#[cfg(feature = "sp1")]
pub mod sp1;

#[cfg(not(feature = "sp1"))]
fn main() {
    #[cfg(feature = "nitro")]
    {
        let _ = nitro::main();
    }
}
