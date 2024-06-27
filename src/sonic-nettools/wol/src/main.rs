mod wol;

extern crate pnet;
extern crate clap;

use wol::wol;

fn main() {
    wol();
}