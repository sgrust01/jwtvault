use jwtvault::prelude::*;
use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;

fn main() {

    let mut users = HashMap::new();

    // User: John Doe
    let user_john = "John Doe";
    let password_for_john = "john";

    // User: Jane Doe
    let user_jane = "Jane Doe";
    let password_for_jane = "jane";

    // load users and their password from database/somewhere
    users.insert(user_john.to_string(), password_for_john.to_string());
    users.insert(user_jane.to_string(), password_for_jane.to_string());

    // Initialize vault
    let mut vault = DefaultVault::new(users);
    println!("== login == ");

    // John needs to login now
    let token = vault.login(
        user_john,
        password_for_john,
        None,
        None,
    ).ok().unwrap().unwrap();

    // When John presents authentication token, it can be used to restore John's session info
    let server_refresh_token = vault.resolve_server_token_from_client_authentication_token(
        user_john.as_bytes(),
        token.authentication_token(),
    ).ok().unwrap();

    // server_refresh_token (variable) contains server which captures client private info
    // which never leaves the server
    let private_info_about_john = server_refresh_token.server().unwrap();

    // server_refresh_token (variable) contains client which captures client public info
    // which is send to client
    let data_from_server_side = server_refresh_token.client().unwrap();

    let client_session = format!("ClientSide: {}", user_john);
    let server_session = format!("ServerSide: {}", user_john);

    let client_session = digest(&mut DefaultHasher::default(), client_session.as_bytes());
    let server_session = digest(&mut DefaultHasher::default(), server_session.as_bytes());
    println!("client_session = {}", digest(&mut DefaultHasher::default(), "client".as_bytes()));
    println!("server_session = {}", digest(&mut DefaultHasher::default(), "server".as_bytes()));

    println!("{:#?}", data_from_server_side);
    println!("{:#?}", private_info_about_john);



    // Check out the data on client and server which are public and private respectively
    println!(" [Public] John Info: {}",
             String::from_utf8_lossy(data_from_server_side.get(&client_session).unwrap().as_slice()).to_string());
    println!("[Private] John Info: {}",
             String::from_utf8_lossy(private_info_about_john.get(&server_session).unwrap().as_slice()).to_string());

    // lets renew authentication token
    let new_token = vault.renew(
        user_john.as_bytes(),
        token.refresh_token(),
        None,
    ).ok().unwrap();

    // When John presents new authentication token it can be used to restore session info
    let _ = vault.resolve_server_token_from_client_authentication_token(
        user_john.as_bytes(), new_token.as_str(),
    ).ok().unwrap();
}