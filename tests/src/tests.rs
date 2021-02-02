use super::*;

use ckb_testtool::{builtin::ALWAYS_SUCCESS, context::Context};
use ckb_tool::ckb_types::{
    bytes::Bytes,
    core::{TransactionBuilder},
    packed::*,
    prelude::*,
};
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey};
use openssl::rsa::Rsa;
use openssl::sign::{Verifier};
use std::fs;
use openssl::bn::{BigNum};

const MAX_CYCLES: u64 = 70_000_000;

#[test]
fn test_rsa_signature_verifying() {
    
    let message = Bytes::from(
            hex::decode("2a8434db3224e208c61dfd521953974092d13b6859558a054dfd5a390203e704")
                .unwrap());
    let rsa_signature = Bytes::from(
            hex::decode("703dd4f2f37df8d4a21cab60507bf5dbe45323510db90c0a3794282dbfea1c09727a268d1e7ccc94162df288a6ee1470815858052708dc09e3f007d4fdd328785caa05872acaa685d863714e820edb3a10624c260ebacf6085ee60deedf4d83985352e71f1de9c11c92dbaafebd8dc94d91c2e7cef21353043503c92d7411477b36991f3aff187cf2ab5cd3d00b0c2f6008f281bb8d73fc0ec78dab58c99a9e772524b51c81963ea2602932e7a2a6e6690f072b7c16398d87401d1c7016459795e016793861b49f779e0f546dae9f16319311c87349ba58317b602c4354593415a92905e0e3732634cb23e9027a33ca32dceba75052b6ed3d420531b59612e59ac2d51ceaca7bd426ea39eddf37b7e3f943bde3264ef546e06f2adbd055f7232d95610ef8db0eafcc961eeb63dc1ad1232e096ec0cc6b20b2534afd15b7b4f2458597e303af854a3ce8aa49fe091dca57a42ca895988aee5907ca5db63e042d0b804302a245bd2e0deb5b19e53e5dacfd883d9899610f8f147b79fb4e89462ba4c4f66fd5b44c170a91e3dc536d77b6a8ff27e5a9da324465fe396451ae0de3c1c4101e10bd52b57b9e4f3798022d93efa8784b541871ac260bc2fb403adc47eb45f31eb891ff521d6d7e0ff19d99c8aa94d653c7bc30b1d2cb92227b3d86df42cdeef155b3efd120de647935929d59193aada427eaf4700e2518c3a6f121089")
                .unwrap());
    let public_key = Rsa::from_public_components(BigNum::from_hex_str("816e41adce645c5002fd3d07ca68010dfd77db79a587624a0621603776784e0fbd4a6f0ee2eedc50806bbd5335997f98b025752ddbf22ce358fb656616dd6eb40c5004cbf5c7663e8e5530844fbffdd9559260f683663947693fcb242150a5dd61dc6795562b71679f647bded1fa9c6140171acacfbd399b4a57796a4f42fd3633e027bcdb01e54783458b4c944aa655e46e032d6242f52e0bc11c4a08e59f856043700fa32396f540f918784cf7d5dd9a081b0a97b0d60d9e360f11862c5dafd6d40069fad00c79e9a3f9d8cab0f671db908b714023b8ed31520c95f8bf6b01c07f327d8e9b36d97be75adfda575c07d0bcb1f1b6cac26874ca081ff4c2d38f").unwrap(), BigNum::from_dec_str("65537").unwrap()).unwrap();
    
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