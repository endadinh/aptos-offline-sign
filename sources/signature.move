module aptos_signature::signature {

  use std::hash;
  use std::signer;
  use std::vector;
  use std::bcs;
  use aptos_std::from_bcs;
  use aptos_std::math64;
  use aptos_std::any;
  use aptos_framework::account;
  use aptos_framework::event;
  use aptos_framework::chain_id;
  use aptos_std::aptos_hash;
  use aptos_std::ed25519::{
        new_signature_from_bytes,
        signature_verify_strict,
        new_unvalidated_public_key_from_bytes,
  };

  struct Check has key {
    whitelist_id: u64,
    message_bytes: vector<u8>,
    is_valid: bool,
    check_events: event::EventHandle<CheckEvent>,
  }

  struct Root has key { 
    root: vector<u8>,
    save_events: event::EventHandle<SaveEvent>,
  }

  struct CheckEvent has drop, store {
    whitelist_id: u64,
    struct_msg: MessageTypeHash,
    struct_bytes: vector<u8>,
    addr_bytes: vector<u8>,
    message_bytes: vector<u8>,
    chain_id: u8,
    is_valid: bool,
    signature: vector<u8>,
  }

  struct SaveEvent has drop,store { 
    root: vector<u8>,
  }

  struct MessageTypeHash has drop,store {
    whitelist_id: u64,
    chain_id: u8,
  }

  const COMPARE_EQUAL: u8 = 127u8;

  public entry fun set_root(
    account: signer,
    root: vector<u8> 
  ) acquires Root {
    let addr = signer::address_of(&account);
    if(exists<Root>(addr)) { 
        let new_root = borrow_global_mut<Root>(addr);
        new_root.root = root;
        event::emit_event(&mut new_root.save_events,  SaveEvent { 
        root,
        });
    }
    else { 
        let new_root = Root { 
            root,
            save_events: account::new_event_handle<SaveEvent>(&account),
        };
        event::emit_event(&mut new_root.save_events, SaveEvent { 
            root
        });
        move_to(&account, new_root);
    };
  }

  public entry fun execute_verify(
    account: signer, 
    whitelist_id: u64,
    signature: vector<u8>
  ) acquires Root,Check{ 
    let account_addr = signer::address_of(&account);
    assert!(exists<Root>(account_addr), 101u64);
    let root_check = borrow_global<Root>(account_addr);
    // let addr_byte = bcs::to_bytes<address>(&signer::address_of(&account));
    // vector::append(&mut addr_byte, params);
    // let message_bytes = aptos_hash::keccak256(addr_byte);

     let msg = MessageTypeHash { 
            whitelist_id : whitelist_id ,
            chain_id     : chain_id::get(),
        }; 

     let msg_bytes = bcs::to_bytes<MessageTypeHash>(&msg);

    let message_bytes = get_message_type_hash(whitelist_id, account_addr);

    let is_valid = verify_signature(root_check.root, signature, message_bytes);
    let root = root_check.root;
      let addr_b = bcs::to_bytes<address>(&account_addr);

    if (exists<Check>(account_addr)) {
      let check = borrow_global_mut<Check>(account_addr);
        check.whitelist_id= whitelist_id;
        check.message_bytes= message_bytes;
        check.is_valid= is_valid;


      event::emit_event(&mut check.check_events, CheckEvent {
        whitelist_id: whitelist_id,
        struct_msg: msg,
        struct_bytes: msg_bytes,
        addr_bytes: addr_b,
        message_bytes: message_bytes,
        chain_id: chain_id::get(),
        is_valid: is_valid,
        signature
      });
    } else {
      let check = Check {
        whitelist_id: whitelist_id,
        message_bytes,
        is_valid,
        check_events: account::new_event_handle<CheckEvent>(&account),
      };

      event::emit_event(&mut check.check_events, CheckEvent {
        whitelist_id: whitelist_id,
        struct_msg: msg,
        struct_bytes: msg_bytes,
        addr_bytes: addr_b,
        message_bytes: message_bytes,
        chain_id: chain_id::get(),
        is_valid: is_valid,
        signature
      });

      move_to(&account, check);
    }
  }

    public fun verify_signature(authority_pubkey: vector<u8>, signature_byte: vector<u8>, message: vector<u8>): bool {
        let public_key = new_unvalidated_public_key_from_bytes(authority_pubkey);
        let signature = new_signature_from_bytes(signature_byte);
        let status = signature_verify_strict(&signature, &public_key, message);
        (status)
    }

    public fun get_message_type_hash(whitelist_id: u64, sender_addr: address): vector<u8> {
        let addr_bytes = bcs::to_bytes<address>(&sender_addr);
        let msg = MessageTypeHash { 
            whitelist_id : whitelist_id ,
            chain_id     : chain_id::get(),
        };  
        let msg_bytes = bcs::to_bytes<MessageTypeHash>(&msg);
        vector::append(&mut msg_bytes,addr_bytes);
        let msg_hash = aptos_hash::keccak256(msg_bytes);
        (msg_hash)
    }
}