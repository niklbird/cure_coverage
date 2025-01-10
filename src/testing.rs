use bls_signatures::PrivateKey;

pub fn test(){
    let mut rng = rand::thread_rng();

    let mut public_keys = vec![];
    let mut signatures = vec![];
    let mut messages = vec![];

    for i in 0..20{
        let pk = PrivateKey::generate(&mut rng);

        let pub_key = pk.public_key();
    
        // Random message
        let random_msg = format!("message {}", i);
        let signature = pk.sign(&random_msg);
    
        public_keys.push(pub_key);
        signatures.push(signature);
        messages.push(random_msg.clone());
    }

    signatures.remove(0);

    let mut messages_b = vec![];
    for i in 0..messages.len() {
        let m = messages.get(i).unwrap();
        messages_b.push(m.as_bytes());
    }

    let aggr = bls_signatures::aggregate(signatures.as_slice()).unwrap();
    let vm = bls_signatures::verify_messages(&aggr, &messages_b, &public_keys);

    println!("Is valid {}", vm);

}