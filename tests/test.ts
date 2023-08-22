import { MessageTypeHash } from './../common/ts/client';
import { AptosAccount, AptosClient, CoinClient, FaucetClient, HexString, MaybeHexString, TokenClient, } from "aptos"
import { get_hash_message, HashWhitelistMessage, signAndSendTransaction, signMessage } from "../common/ts/client";
import BN from 'bn.js';


const FAUCET_URL = "http://localhost:8081"

const NODE_URL = "http://localhost:8080"

describe("Hello Aptos", () => {
    // APTOS CLIENT DEFINED
    let client: AptosClient
    let faucetClient: FaucetClient
    let coinClient: CoinClient
    let tokenClient: TokenClient

    // ACCOUNT DEFINED
    let defaultAccount: AptosAccount
    let deployerAccount: AptosAccount
    let resourceAccount: AptosAccount
    let userAccount: AptosAccount

    const CONTRACT_ADDRESS = '0xb97365d79fdcf0f1d3b15c5b1113ea73a0552ead2a0ce11fccf19a3ab083b3b9';

    before("Create Connection", async () => {
        client = new AptosClient(NODE_URL);
        faucetClient = new FaucetClient(NODE_URL,FAUCET_URL);

        // Create a coin client for checking account balances.
        coinClient = new CoinClient(client);
        tokenClient = new TokenClient(client);
        let privateKeyBytes_deployer = new TextEncoder().encode("0xcf1dba923857a907f2c784bccf960fc4dee1e21235f3ed8019d315a634a32f13");
        let privateKeyBytes_resource = new TextEncoder().encode("0xde1fd2dc6c501e80d28fb74ae9929f6473d93302101f78437a7e44245133cdea");
        let privateKeyBytes_user = new TextEncoder().encode("0x55ce7b24f7d89cdd22a055f29ee5f70996976f95a5e702fde8915ba92b9b5bcc");

        // Create accounts from seed.
        deployerAccount = new AptosAccount(privateKeyBytes_deployer);
        resourceAccount = new AptosAccount(privateKeyBytes_resource);
        userAccount = new AptosAccount(privateKeyBytes_user);
        defaultAccount = new AptosAccount(Uint8Array.from([137, 206, 72, 75, 226, 122, 39, 49, 67, 110, 36, 246, 102, 108, 115, 237, 24, 99, 195, 4, 211, 249, 143, 123, 220, 13, 202, 94, 219, 38, 210, 58]));
        await faucetClient.fundAccount(defaultAccount.address(), 100000000);

        const deployerPrivateKey = await deployerAccount.toPrivateKeyObject();
        const resourcePrivateKey = await resourceAccount.toPrivateKeyObject();
        const userPrivateKey = await userAccount.toPrivateKeyObject();
        const defaultPrivateKey = await defaultAccount.toPrivateKeyObject();

        // Print out account .
        console.log("=== Account generated ===");

        console.log(`Deployer Address: ${deployerAccount.address()}`);
        console.log(`Deployer private key : ${deployerPrivateKey.privateKeyHex}`)
        console.log(`Deployer Public key : ${deployerPrivateKey.publicKeyHex}`)

        console.log(`Resource Address: ${resourceAccount.address()}`);
        console.log(`Resource PrivateKey: ${resourcePrivateKey.privateKeyHex}`);
        console.log(`Resource Public Key: ${resourcePrivateKey.publicKeyHex}`);

        console.log(`User Address: ${userAccount.address()}`);
        console.log(`User PrivateKey: ${userPrivateKey.privateKeyHex}`);
        console.log(`User Public Key: ${userPrivateKey.publicKeyHex}`);


        console.log(`Default Address: ${defaultAccount.address()}`);
        console.log(`Default PrivateKey: ${defaultPrivateKey.privateKeyHex}`);
        console.log(`Default Public Key: ${defaultPrivateKey.publicKeyHex}`);
        

        // Fund accounts.

        await faucetClient.fundAccount(deployerAccount.address(), 100_000_000);
        await faucetClient.fundAccount(resourceAccount.address(), 100_000_000);
        await faucetClient.fundAccount(userAccount.address(), 100_000_000);

        console.log("=== Initial Coin Balances ===");
        console.log(`Deployer: ${await coinClient.checkBalance(deployerAccount)}`);
        console.log(`Resource: ${await coinClient.checkBalance(resourceAccount)}`);
        console.log(`User: ${await coinClient.checkBalance(userAccount)}`);
        console.log("");

        // INIT SCHEDULE WHITELIST
    })

    it('set_root test', async function() { 
        let root = defaultAccount.signingKey.publicKey;

        let whitelist_id = 101;


        let whitelist_bytes = Buffer.from(whitelist_id.toString(16));


        let whitelist_array = Uint8Array.from(whitelist_bytes)


        const tx = await client.generateTransaction(deployerAccount.address(), {
            function: `${CONTRACT_ADDRESS}::signature::set_root`,
            type_arguments: [],
            arguments: [root]
        });

        await signAndSendTransaction(
            client,
            tx,
            deployerAccount
        );
    });

    it('verify test', async function() { 
        let whitelist_id = new BN(101)
        let whitelist_bytes = Buffer.from(whitelist_id.toString(16));
        let whitelist_array = Uint8Array.from(whitelist_bytes)

        let msg: MessageTypeHash = {
            whitelist_id: whitelist_id,
            chain_id: await client.getChainId(),
        }
        let msg_type_hash = HashWhitelistMessage(msg)
        
        console.log('struct type', HexString.fromBuffer(msg_type_hash));
        let msg_hash = await get_hash_message(client,msg_type_hash,deployerAccount.address())
        console.log('hash',HexString.fromBuffer(msg_hash));

        let signature = await signMessage(defaultAccount,msg_hash);

        const tx = await client.generateTransaction(deployerAccount.address(), {
            function: `${CONTRACT_ADDRESS}::signature::execute_verify`,
            type_arguments: [],
            arguments: [101,signature]
        });

        await signAndSendTransaction(
            client,
            tx,
            deployerAccount
        );

    });
})