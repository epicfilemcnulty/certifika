mod acme;

fn main() {
    let dir = acme::Directory::lets_encrypt().unwrap();
    let account = dir.register_account("vzr006@gmail.com").unwrap();
    println!("{:?}", account);
}
