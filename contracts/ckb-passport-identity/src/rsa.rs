use core::result::Result;
use crate::error::Error;
use alloc::vec::Vec;
use ckb_lib_rsa::LibRSA;

pub fn verify_rsa(lib: &LibRSA, n: &[u8], e: u32, msg: &[u8], sig: &[u8]) -> Result<(), Error> {
    let rsa_info = generate_rsa_info(&n, e, &sig)?;
    match lib.validate_signature(rsa_info.as_ref(), &msg) {
      Ok(_) => Ok(()),
      Err(_) => Err(Error::RSAVerifyError)
    }
}

/** signature (in witness, or passed as arguments) memory layout
 * This structure contains the following information:
 * 1) Common header, 4 bytes
 * 2) RSA Public Key
 * 3) RSA Signature data
 *
-----------------------------------------------------------------------------
|common header| E |  N (KeySize/8 bytes) | RSA Signature (KeySize/8 bytes)|
-----------------------------------------------------------------------------
The common header includes algorithm_id, key_size, padding, md_type whose data type are uint8_t.
The common header, E both occupy 4 bytes. E is in little endian(uint32_t).
The N must be little endian with [u8; 128]
So the total length in byte is: 4 + 4 + KeySize/8 + KeySize/8.
*/
fn generate_rsa_info(n: &[u8], e: u32, sig: &[u8]) -> Result<Vec<u8>, Error> {
  if n.len() != sig.len() {
    return Err(Error::RSAPubKeySigLengthError)
  }

  let pub_key_size: u32 = (n.len() as u32) * 8;
  let rsa_info_len = pub_key_size / 4 + 8;

  let mut rsa_info = Vec::new();
  for _ in 0..rsa_info_len {
    rsa_info.push(0u8);
  }

  rsa_info[0..4].copy_from_slice(&get_common_header());
  rsa_info[4..8].copy_from_slice(&e.to_le_bytes());
  rsa_info[8..(8 + n.len())].copy_from_slice(&n);
  rsa_info[(8 + n.len())..(8 + n.len() * 2)].copy_from_slice(&sig);

  Ok(rsa_info)
}

const RSA_ALGORITHM_ID: u8 = 1;
const RSA_KEY_SIZE: u8 = 3;
const RSA_PADDING: u8 = 0;
const RSA_MD_SHA256: u8 = 6;
pub fn get_common_header() -> [u8; 4] {
  [RSA_ALGORITHM_ID, RSA_KEY_SIZE, RSA_PADDING, RSA_MD_SHA256]
}