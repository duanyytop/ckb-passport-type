use core::result::Result;

use ckb_std::{
    high_level::load_cell_data,
    ckb_constants::Source,
    dynamic_loading::CKBDLContext,
};

use crate::error::Error;
use super::rsa;

const MSG_LEN: usize = 32;
const SIGNATURE_LEN: usize = 512;
const PUBLIC_KEY_E_LEN: usize = 4; 
const PUBLIC_KEY_N_LEN: usize = 512;
const DATA_LEN: usize = 676;

pub fn main() -> Result<(), Error> {
    let mut context = unsafe { CKBDLContext::<[u8; 1024 * 128]>::new() };

    let data = load_cell_data(0, Source::GroupOutput)?;
    if data.len() != DATA_LEN {
        return Err(Error::DataLenError);
    }
    
    let mut pub_key_e = [0u8; PUBLIC_KEY_E_LEN];
    let mut pub_key_n = [0u8; PUBLIC_KEY_N_LEN];
    let mut message = [0u8; MSG_LEN];
    let mut signature = [0u8; SIGNATURE_LEN];
    pub_key_e.copy_from_slice(&data[0..PUBLIC_KEY_E_LEN]);
    pub_key_n.copy_from_slice(&data[PUBLIC_KEY_E_LEN..(PUBLIC_KEY_E_LEN + PUBLIC_KEY_N_LEN)]);
    message.copy_from_slice(&data[(PUBLIC_KEY_E_LEN + PUBLIC_KEY_N_LEN)..(DATA_LEN - SIGNATURE_LEN)]);
    signature.copy_from_slice(&data[(DATA_LEN - SIGNATURE_LEN)..]);

    let pub_key_e = u32::from_le_bytes(pub_key_e);

    let lib = ckb_lib_rsa::LibRSA::load(&mut context);

    rsa::verify_rsa(&lib, &pub_key_n, pub_key_e, &message, &signature)
}

