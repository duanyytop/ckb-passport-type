use super::*;

use ckb_testtool::{builtin::ALWAYS_SUCCESS, context::Context};
use ckb_tool::ckb_types::{
    bytes::Bytes,
    core::{TransactionBuilder},
    packed::*,
    prelude::*,
};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sign::{Signer, Verifier};
use std::fs;
use openssl::bn::{BigNum};

const MAX_CYCLES: u64 = 70_000_000;

fn generate_random_key() -> (PKey<Private>, PKey<Public>) {
    let rsa = Rsa::generate(4096).unwrap();
    let private_key = PKey::from_rsa(rsa).unwrap();

    let public_key_pem: Vec<u8> = private_key.public_key_to_pem().unwrap();
    let public_key = PKey::public_key_from_pem(&public_key_pem).unwrap();
    (private_key, public_key)
}

fn compute_pub_key(public_key: &PKey<Public>) -> Vec<u8> {
    let mut result: Vec<u8> = vec![];
    let rsa_public_key = public_key.rsa().unwrap();
    let mut e = rsa_public_key.e().to_vec();
    let mut n = rsa_public_key.n().to_vec();
    e.reverse();
    n.reverse();

    while e.len() < 4 {
        e.push(0);
    }
    while n.len() < 128 {
        n.push(0);
    }

    result.append(&mut e);
    result.append(&mut n);

    result
}

#[test]
fn test_rsa_signature_verifying1() {
    let (private_key, public_key) = generate_random_key();
    let message = Bytes::from(
            hex::decode("2a8434db3224e208c61dfd521953974092d13b6859558a054dfd5a390203e704")
                .unwrap());

    // openssl
    let mut signer = Signer::new(MessageDigest::sha256(), &private_key).unwrap();
    signer.update(&message).unwrap();
    let mut rsa_signature = signer.sign_to_vec().unwrap();

    // verify it locally
    let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key).unwrap();
    verifier.update(&message).unwrap();
    assert!(verifier.verify(&rsa_signature).unwrap());

    let mut data = compute_pub_key(&public_key).to_vec();
    println!("public_key len: {:?}", data.len());
    println!("message len: {:?}", message.len());
    println!("rsa_signature len: {:?}", rsa_signature.len());
    data.append(&mut message.to_vec());
    data.append(&mut rsa_signature);

    println!("data len: {:?}", data.len());
    
    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ckb-passport-identity");
    let type_out_point = context.deploy_cell(contract_bin);
    let passport_type_dep = CellDep::new_builder().out_point(type_out_point.clone()).build();

    let passport_type_args = Bytes::from(
            hex::decode("c449b9d7916e66670660da045a63c78a810f8aa9f032c9ee167d3d9bcb0e56b1")
                .unwrap());
    let passport_type_script = context
        .build_script(&type_out_point, passport_type_args)
        .expect("script");

    // deploy always_success script
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_dep = CellDep::new_builder().out_point(always_success_out_point.clone()).build();

    let lock_args = Bytes::from(
            hex::decode("23c329ed630d6ce750712a477543672adab57f4c")
                .unwrap());
    // build lock script
    let always_success_lock_script = context
        .build_script(&always_success_out_point, lock_args)
        .expect("script");

    let rsa_bin: Bytes = fs::read("../ckb-production-scripts/build/validate_signature_rsa")
        .expect("load rsa")
        .into();
    let rsa_out_point = context.deploy_cell(rsa_bin);
    let rsa_dep = CellDep::new_builder().out_point(rsa_out_point).build();

    // prepare cells
    let input_out_point1 = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(always_success_lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input_out_point2 = context.create_cell(
        CellOutput::new_builder()
            .capacity(300u64.pack())
            .lock(always_success_lock_script.clone())
            .build(),
        Bytes::new(),
    );

    let inputs = vec![
        CellInput::new_builder()
            .previous_output(input_out_point1)
            .build(),
        CellInput::new_builder()
            .previous_output(input_out_point2)
            .build(),
    ];
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(always_success_lock_script.clone())
            .type_(ScriptOpt::new_builder().set(Some(passport_type_script)).build())
            .build(),
        CellOutput::new_builder()
            .capacity(800u64.pack())
            .lock(always_success_lock_script)
            .build(),
    ];

    let outputs_data = vec![Bytes::copy_from_slice(&data[..]), Bytes::new()];
    let mut witnesses = vec![];
    for _ in 0..inputs.len() {
        witnesses.push(Bytes::new())
    }

    // build transaction
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(always_success_dep)
        .cell_dep(passport_type_dep)
        .cell_dep(rsa_dep)
        .witnesses(witnesses.pack())
        .build();
    let tx = context.complete_tx(tx);

    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_rsa_signature_verifying2() {
    
    let message = Bytes::from(
            hex::decode("2a8434db3224e208c61dfd521953974092d13b6859558a054dfd5a390203e704")
                .unwrap());
    let rsa_signature = Bytes::from(
            hex::decode("703dd4f2f37df8d4a21cab60507bf5dbe45323510db90c0a3794282dbfea1c09727a268d1e7ccc94162df288a6ee1470815858052708dc09e3f007d4fdd328785caa05872acaa685d863714e820edb3a10624c260ebacf6085ee60deedf4d83985352e71f1de9c11c92dbaafebd8dc94d91c2e7cef21353043503c92d7411477b36991f3aff187cf2ab5cd3d00b0c2f6008f281bb8d73fc0ec78dab58c99a9e772524b51c81963ea2602932e7a2a6e6690f072b7c16398d87401d1c7016459795e016793861b49f779e0f546dae9f16319311c87349ba58317b602c4354593415a92905e0e3732634cb23e9027a33ca32dceba75052b6ed3d420531b59612e59ac2d51ceaca7bd426ea39eddf37b7e3f943bde3264ef546e06f2adbd055f7232d95610ef8db0eafcc961eeb63dc1ad1232e096ec0cc6b20b2534afd15b7b4f2458597e303af854a3ce8aa49fe091dca57a42ca895988aee5907ca5db63e042d0b804302a245bd2e0deb5b19e53e5dacfd883d9899610f8f147b79fb4e89462ba4c4f66fd5b44c170a91e3dc536d77b6a8ff27e5a9da324465fe396451ae0de3c1c4101e10bd52b57b9e4f3798022d93efa8784b541871ac260bc2fb403adc47eb45f31eb891ff521d6d7e0ff19d99c8aa94d653c7bc30b1d2cb92227b3d86df42cdeef155b3efd120de647935929d59193aada427eaf4700e2518c3a6f121089")
                .unwrap());
    let public_key = Rsa::from_public_components(BigNum::from_hex_str("AA564A16FB1BF8AA5364EA46BF9979361BA05CF8A79C3E32C929E12987B185E5CAB8A67A3F9054E62AD491FEA67B36B4DF6A6833917DB4F9B50E2A4DE8E4F8AEA5C46598697D082174B8AF346CF0F9707E29304AFF4F64FAB92DFAF3B56D9E58B2838D8F72ACE5A7B0697E9F1294D69869BD63394203DFD6874D6C7F422592F03F9372CBCD70A75AB6A19A7E1BA089D1C3E446CB595E88CB0529A496EB2B9CC13296F5DDE31C20DDE5D93A132E905C343A654AD8D8792B48DF027AE7CF077B8977BF1B48A581ABA7E9A2A4C51F535EAA190FED3D0EC5193EB9896B87803A711164D1538C6963194ACA6430006AA0B4C69F02D40644198290DE4C3A96880F041E5CBBDC6527C201C9367F610A664C816D918B9EAD389A5362A828ACD14D124DBC0DD83A86E23DAE6ABB2E5CCE1D264E22ED2F567BF90576D8BAF4A39AD702D9906A210F91DA69774F664EB0C9E51EC48CE17516B5403DE86CE340F8E00A28B5BD5A5EA614D20F873B4BC2545C23F8F668B70A1E63D0CD53A2CEE4DEACE50731785AE048731396436CA059DFE717F8A6A52F0C084CFBF44B80B034129704587294DED5EFC612FCF88E17778AB559AA2C3526127D31FABED889C08ADDEA0F62C627CFEDB0A551091E3013B20471CB127A205598A0DB9F7A3B39E4C590F20A04853ED7EED649863D200DF30A80735AD5744D5A432530AABADE5847888AE43E7BAB8F").unwrap(), BigNum::from_dec_str("65537").unwrap()).unwrap();
    
    let public_key = PKey::from_rsa(public_key).unwrap();

    let mut verifier = Verifier::new(MessageDigest::sha256(), &public_key).unwrap();
    verifier.update(&message).unwrap();
    assert!(verifier.verify(&rsa_signature).unwrap());

    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ckb-passport-identity");
    let type_out_point = context.deploy_cell(contract_bin);
    let passport_type_dep = CellDep::new_builder().out_point(type_out_point.clone()).build();

    let passport_type_args = Bytes::from(
            hex::decode("c449b9d7916e66670660da045a63c78a810f8aa9f032c9ee167d3d9bcb0e56b1")
                .unwrap());
    let passport_type_script = context
        .build_script(&type_out_point, passport_type_args)
        .expect("script");

    // deploy always_success script
    let always_success_out_point = context.deploy_cell(ALWAYS_SUCCESS.clone());
    let always_success_dep = CellDep::new_builder().out_point(always_success_out_point.clone()).build();

    let lock_args = Bytes::from(
            hex::decode("23c329ed630d6ce750712a477543672adab57f4c")
                .unwrap());
    // build lock script
    let always_success_lock_script = context
        .build_script(&always_success_out_point, lock_args)
        .expect("script");

    let rsa_bin: Bytes = fs::read("../ckb-production-scripts/build/validate_signature_rsa")
        .expect("load rsa")
        .into();
    let rsa_out_point = context.deploy_cell(rsa_bin);
    let rsa_dep = CellDep::new_builder().out_point(rsa_out_point).build();

    // prepare cells
    let input_out_point1 = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(always_success_lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input_out_point2 = context.create_cell(
        CellOutput::new_builder()
            .capacity(300u64.pack())
            .lock(always_success_lock_script.clone())
            .build(),
        Bytes::new(),
    );

    let inputs = vec![
        CellInput::new_builder()
            .previous_output(input_out_point1)
            .build(),
        CellInput::new_builder()
            .previous_output(input_out_point2)
            .build(),
    ];
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(always_success_lock_script.clone())
            .type_(ScriptOpt::new_builder().set(Some(passport_type_script)).build())
            .build(),
        CellOutput::new_builder()
            .capacity(800u64.pack())
            .lock(always_success_lock_script)
            .build(),
    ];

    let outputs_data = vec![Bytes::new(); 2];
    let mut witnesses = vec![];
    for _ in 0..inputs.len() {
        witnesses.push(Bytes::new())
    }

    // build transaction
    let tx = TransactionBuilder::default()
        .inputs(inputs)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(always_success_dep)
        .cell_dep(passport_type_dep)
        .cell_dep(rsa_dep)
        .witnesses(witnesses.pack())
        .build();
    let tx = context.complete_tx(tx);

    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}