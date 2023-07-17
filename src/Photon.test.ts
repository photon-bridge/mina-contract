import {
  CelestiaMerkleWitnessClass,
  SignerMerkleWitnessClass,
  Signer,
  Block,
  BlockProof,
  SignerProof,
  Photon
} from './Photon';
import {
  AccountUpdate,
  Bool,
  Field,
  MerkleTree,
  Mina,
  Poseidon,
  PrivateKey,
  PublicKey,
  Reducer,
  Signature
} from 'snarkyjs';

let proofsEnabled = false;

const MAX_CELESTIA_MERKLE_TREE_HEIGHT = 17; // The Celestia merkle tree can hold at most 2^32 (4294967296) block hashes.
const MAX_CELESTIA_BLOCK_COUNT = 65536; // Max 524288 blocks are supported. This number can be increased if needed, but do not forget to change the MAX_CELESTIA_MERKLE_TREE_HEIGHT as well.
const MAX_SIGNER_MERKLE_TREE_HEIGHT = 9; // The Signer merkle tree can hold at most 2^10 (1024) signers.
const MAX_SIGNER_COUNT = 200; // Max 1000 signers are supported. This number can be increased if needed, but do not forget to change the MAX_SIGNER_MERKLE_TREE_HEIGHT as well.

const celestiaData: string[] = [];

const FORMATTED_CHAR_LENGTH = 4;

function formatChar(_char: string) {
  let char = _char;

  while (char.length < FORMATTED_CHAR_LENGTH)
    char = '0' + char;

  return char;
};

function formatCharCode(charCode: number) {
  return (charCode % Math.pow(10, FORMATTED_CHAR_LENGTH + 1)).toString();
};

function stringToBigInt(str: string) {
  let resultString = '';

  str.trim().split('').forEach(char => {
    resultString += formatChar(formatCharCode(char.charCodeAt(0)));
  });

  return BigInt(resultString) % Field.ORDER;
};

function pushToCelestia(str: string): number {
  celestiaData.push(str);
  return celestiaData.length - 1;
};

function sign(
  signerPrivateKey: PrivateKey,
  block: Block
): Signature {
  // console.log(stringToBigInt(celestiaData[0]));
  // console.log(block.data.toBigInt());
  // console.log(block.height.toBigInt());

  const dataPoint = celestiaData.find((each, index) => stringToBigInt(each) ==  block.data.toBigInt() && BigInt(index) == block.height.toBigInt());
  if (!dataPoint)
    throw new Error(`No data point found for this height.`);

  return Signature.create(signerPrivateKey, [block.hash()]);
};

describe('Test', () => {
  let deployerAccount: PublicKey,
    deployerKey: PrivateKey,
    senderAccount: PublicKey,
    senderKey: PrivateKey,
    zkAppAddress: PublicKey,
    zkAppPrivateKey: PrivateKey,
    zkApp: Photon;

  const SIGNER_COUNT = 5;
  const signerPrivateKeys = Array.from({ length: SIGNER_COUNT }, _ => PrivateKey.random());

  beforeAll(async () => {
    if (proofsEnabled) await Photon.compile();
  });

  beforeEach(async () => {
    const Local = Mina.LocalBlockchain({ proofsEnabled });
    Mina.setActiveInstance(Local);
    ({ privateKey: deployerKey, publicKey: deployerAccount } =
      Local.testAccounts[0]);
    ({ privateKey: senderKey, publicKey: senderAccount } =
      Local.testAccounts[1]);
    zkAppPrivateKey = PrivateKey.random();
    zkAppAddress = zkAppPrivateKey.toPublicKey();
    zkApp = new Photon(zkAppAddress);

    console.log(Local.testAccounts[0].privateKey.toBase58())

    for (let i = 2; i < 2 + SIGNER_COUNT; i++)
      signerPrivateKeys[i - 2] = Local.testAccounts[i].privateKey;

    await localDeploy();

    const celestiaTree = new MerkleTree(MAX_CELESTIA_MERKLE_TREE_HEIGHT);
    const signerTree = new MerkleTree(MAX_SIGNER_MERKLE_TREE_HEIGHT);

    for (let i = 0; i < 100; i++)
      celestiaTree.setLeaf(BigInt(i), Block.empty().hash());

    for (let i = 0; i < SIGNER_COUNT; i++) {
      signerTree.setLeaf(BigInt(i), new Signer(
        signerPrivateKeys[i].toPublicKey(),
        SignerMerkleWitnessClass.empty(), // Hash does not depend on the witness, so this is fine.
        Field(0)
      ).hash());
    }
    for (let i = SIGNER_COUNT; i < MAX_SIGNER_COUNT; i++)
      signerTree.setLeaf(BigInt(i), Signer.empty().hash());

    const txn = await Mina.transaction(deployerAccount, () => {
      zkApp.initialize(
        celestiaTree.getRoot(),
        Field(SIGNER_COUNT),
        signerTree.getRoot()
      );
    });
    await txn.prove();
    await txn.sign([deployerKey, zkAppPrivateKey]).send();
  });

  async function localDeploy() {
    const txn = await Mina.transaction(deployerAccount, () => {
      AccountUpdate.fundNewAccount(deployerAccount);
      zkApp.deploy();
    });
    await txn.prove();
    // this tx needs .sign(), because `deploy()` adds an account update that requires signature authorization
    await txn.sign([deployerKey, zkAppPrivateKey]).send();
  }

  it('Test 1: Initialize the Contract', async () => {
    const celestiaTree = new MerkleTree(MAX_CELESTIA_MERKLE_TREE_HEIGHT);
    const signerTree = new MerkleTree(MAX_SIGNER_MERKLE_TREE_HEIGHT);

    for (let i = 0; i < 100; i++)
      celestiaTree.setLeaf(BigInt(i), Block.empty().hash());

    for (let i = 0; i < SIGNER_COUNT; i++) {
      signerTree.setLeaf(BigInt(i), new Signer(
        signerPrivateKeys[i].toPublicKey(),
        SignerMerkleWitnessClass.empty(), // Hash does not depend on the witness, so this is fine.
        Field(0)
      ).hash());
    }
    for (let i = SIGNER_COUNT; i < MAX_SIGNER_COUNT; i++)
      signerTree.setLeaf(BigInt(i), Signer.empty().hash());

    expect(zkApp.celestiaBlocksTree.get()).toEqual(celestiaTree.getRoot());
    expect(zkApp.signerCount.get()).toEqual(Field(SIGNER_COUNT));
    expect(zkApp.signersTree.get()).toEqual(signerTree.getRoot());
    expect(zkApp.signersTreeAccumulator.get()).toEqual(Reducer.initialActionState);
  });

  it('Test 2: Add a block to the Celestia Merkle Tree', async () => {
    const newData = "New data json. In real life, this would be a block hash.";

    // Generate Celestia Tree
    const celestiaTree = new MerkleTree(MAX_CELESTIA_MERKLE_TREE_HEIGHT);
    for (let i = 0; i < celestiaData.length; i++)
      celestiaTree.setLeaf(BigInt(i), Poseidon.hash([Field(stringToBigInt(celestiaData[i]))]));

    // Push to Celestia
    const height = pushToCelestia(newData);

    // Create the new block
    const newBlock = new Block(
      Field(stringToBigInt(newData)),
      Field(height),
      new CelestiaMerkleWitnessClass(celestiaTree.getWitness(BigInt(height)))
    );

    // Create the Signer Tree
    const signers = Array.from({ length: SIGNER_COUNT }, (_, i) => new Signer(
      signerPrivateKeys[i].toPublicKey(),
      SignerMerkleWitnessClass.empty(), // Hash does not depend on the witness, so this is fine.
      Field(0)
    ));
    const signerTree = new MerkleTree(MAX_SIGNER_MERKLE_TREE_HEIGHT);
    for (let i = 0; i < SIGNER_COUNT; i++)
      signerTree.setLeaf(BigInt(i), signers[i].hash());
    for (let i = SIGNER_COUNT; i < MAX_SIGNER_COUNT; i++)
      signerTree.setLeaf(BigInt(i), Signer.empty().hash());
    for (let i = 0; i < SIGNER_COUNT; i++) {
      signers[i] = new Signer(
        signerPrivateKeys[i].toPublicKey(),
        new SignerMerkleWitnessClass(signerTree.getWitness(BigInt(i))),
        Field(0)
      );
    }

    // Access the Node API: Get the singed block hash from the first 3 signers
    const signedBlockHash1 = sign(
      signerPrivateKeys[0],
      newBlock
    );
    const signedBlockHash2 = sign(
      signerPrivateKeys[1],
      newBlock
    );
    const signedBlockHash3 = sign(
      signerPrivateKeys[2],
      newBlock
    );
    // Create proofs using signed data and signer information
    const proof1 = new BlockProof(
      signers[0],
      signedBlockHash1,
      Field(height)
    );
    const proof2 = new BlockProof(
      signers[1],
      signedBlockHash2,
      Field(height)
    );
    const proof3 = new BlockProof(
      signers[2],
      signedBlockHash3,
      Field(height)
    );

    // Send the transaction
    const txn = await Mina.transaction(deployerAccount, () => {
      zkApp.update(
        newBlock,
        proof1,
        proof2,
        proof3,
        BlockProof.empty(),
        BlockProof.empty(),
        BlockProof.empty(),
        BlockProof.empty(),
        BlockProof.empty(),
        BlockProof.empty(),
        BlockProof.empty(),
        BlockProof.empty(),
        BlockProof.empty(),
        BlockProof.empty(),
        BlockProof.empty(),
        BlockProof.empty(),
        BlockProof.empty(),
        BlockProof.empty(),
        BlockProof.empty(),
        BlockProof.empty(),
        BlockProof.empty()
      );
    });
    await txn.prove();
    await txn.sign([deployerKey, zkAppPrivateKey]).send();

    // Update local Celestia tree
    celestiaTree.setLeaf(BigInt(height), Poseidon.hash([Field(stringToBigInt(newData))]));

    // Update local Signer tree
    signerTree.setLeaf(BigInt(0), signers[0].sign().hash());
    signerTree.setLeaf(BigInt(1), signers[1].sign().hash());
    signerTree.setLeaf(BigInt(2), signers[2].sign().hash());

    // Check the new Celestia Merkle Tree root
    expect(zkApp.celestiaBlocksTree.get()).toEqual(celestiaTree.getRoot());

    // Check the new Signer Merkle Tree root
    // expect(zkApp.signersTree.get()).toEqual(signerTree.getRoot());
  });
});
