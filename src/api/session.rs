use serde::{Serialize, Deserialize};
use std::collections::HashMap;


#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Token {
    authentication: String,
    refresh: String,
}

impl Token {
    pub fn new(authentication: String, refresh: String) -> Self {
        Self {
            authentication,
            refresh,
        }
    }
    pub fn authentication(&self) -> &String {
        &self.authentication
    }
    pub fn refresh(&self) -> &String {
        &self.refresh
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct Session {
    pub client: Option<HashMap<u64, Vec<u8>>>,
    pub server: Option<HashMap<u64, Vec<u8>>>,
}

impl Session {
    pub fn new(client: Option<HashMap<u64, Vec<u8>>>, server: Option<HashMap<u64, Vec<u8>>>) -> Self {
        Self {
            client,
            server,
        }
    }
}


impl Default for Session {
    fn default() -> Self {
        Session::new(None, None)
    }
}