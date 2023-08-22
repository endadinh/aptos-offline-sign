// import { AptosAccount, AptosClient, CoinClient, FaucetClient, HexString, MaybeHexString, TokenClient,  } from "aptos"

// const NODE_URL = "https://fullnode.devnet.aptoslabs.com"

// export class HelloAptosClient extends AptosClient {
//     constructor() {
//         super(NODE_URL)
//     }

//     async verify( 
//         whitelist_usr: AptosAccount,
//         proof: Uint8Array[],
//         leaf: Uint8Array,
//         root: Uint8Array

//     ): Promise<string> { 
//         const rawTx = await this.generateTransaction(whitelist_usr.address(), { 
//             function: "0xd849853cbe1ae22a80eebf1d57bc0d0258b8c72e8cea601653f994ffaf7132d3::Merkle_tree::verify",
//             type_arguments: [],
//             arguments: [proof,leaf,root]
//         })
//         const bcsTx = await this.signTransaction(whitelist_usr,rawTx);
//         const pendingTx = await this.submitTransaction(bcsTx);
//         return pendingTx.hash;
//     }
// }