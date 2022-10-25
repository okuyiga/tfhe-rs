use tfhe::boolean::client_key::ClientKey;
use tfhe::boolean::gen_keys;
use tfhe::boolean::parameters::TFHE_LIB_PARAMETERS;
use tfhe::boolean::prelude::BinaryBooleanGates;
use tfhe::boolean::server_key::ServerKey;

fn main() {
    // let (cks, sks) = gen_keys();
    let cks = ClientKey::new(&TFHE_LIB_PARAMETERS);
    let sks = ServerKey::new(&cks);

    let left = false;
    let right = true;

    let ct_left = cks.encrypt(left);
    let ct_right = cks.encrypt(right);

    let start = std::time::Instant::now();

    let num_loops: usize = 10000;

    for _ in 0..num_loops {
        let result = sks.and(&ct_left, &ct_right);
    }
    let elapsed = start.elapsed().as_millis() as f64;
    let mean: f64 = elapsed / num_loops as f64;

    println!("{elapsed:?} ms, mean {mean:?} ms");
}
