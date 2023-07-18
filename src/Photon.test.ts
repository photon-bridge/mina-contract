import {
  AccountUpdate,
  Field,
  MerkleTree,
  Mina,
  PrivateKey,
  Poseidon,
  PublicKey,
  Reducer,
  Signature
} from 'snarkyjs';

import {
  CelestiaMerkleWitnessClass,
  SignerMerkleWitnessClass,
  Signer,
  Block,
  BlockProof,
  SignerProof,
  Photon
} from './Photon';

let proofsEnabled = false;

const MAX_CELESTIA_MERKLE_TREE_HEIGHT = 21; // The Celestia merkle tree can hold at most 2^20 (1048576) block hashes.
const MAX_BLOCK_COUNT = 1048576; // Max 1048576 blocks are supported. This number can be increased if needed, but do not forget to change the MAX_CELESTIA_MERKLE_TREE_HEIGHT as well.
const MAX_SIGNER_MERKLE_TREE_HEIGHT = 20; // The Signer merkle tree can hold at most 2^20 (1048576) signers. This is much more than the SIGNER_COUNT, since we do not remove a node from the Signer merkle tree when a Signer is removed.
const MAX_SIGNER_COUNT = 200; // Max 200 signers are supported. This number can be increased if needed.

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

function signBlock(
  signerPrivateKey: PrivateKey,
  block: Block
): Signature {
  // console.log(stringToBigInt(celestiaData[0]));
  // console.log(block.data.toBigInt());
  // console.log(block.height.toBigInt());

  const dataPoint = celestiaData.find((each, index) => stringToBigInt(each) ==  block.commitment.toBigInt() && BigInt(index) == block.height.toBigInt());
  if (!dataPoint)
    throw new Error(`No data point found for this height.`);

  return Signature.create(signerPrivateKey, [block.hash()]);
};

function signSigner(
  signerPrivateKey: PrivateKey,
  signer: Signer
): Signature {
  return Signature.create(signerPrivateKey, [signer.hash()]);
};

describe('Test', () => {
  let deployerAccount: PublicKey,
    deployerKey: PrivateKey,
    senderAccount: PublicKey,
    senderKey: PrivateKey,
    zkAppAddress: PublicKey,
    zkAppPrivateKey: PrivateKey,
    zkApp: Photon;

  const NAMESPACE = stringToBigInt('Photon');
  const SIGNER_COUNT = 5;
  const signerPrivateKeys = Array.from({ length: SIGNER_COUNT + 1 }, _ => PrivateKey.random()); // An extra one for the new Signer test

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

    for (let i = 2; i < 2 + SIGNER_COUNT; i++)
      signerPrivateKeys[i - 2] = Local.testAccounts[i].privateKey;

    await localDeploy();

    // Initialize the contract with the given values

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
        Field(NAMESPACE),
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
    // this tx needs .signBlock(), because `deploy()` adds an account update that requires signature authorization
    await txn.sign([deployerKey, zkAppPrivateKey]).send();
  };

  it('Test 1: Initialize the Contract with the given values and check the state is updated as expected.', async () => {
    // No need to send and transactions as there is beforeEach call doing the initilization.

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

  it('Test 2: Add a valid block to the Celestia Merkle Tree and check the state is updated as expected.', async () => {
    const newData = "New data json. In real life, this would be a block commitment.";

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
    const signedBlockHash1 = signBlock(
      signerPrivateKeys[0],
      newBlock
    );
    const signedBlockHash2 = signBlock(
      signerPrivateKeys[1],
      newBlock
    );
    const signedBlockHash3 = signBlock(
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
        BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty()
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

  //// Additional Tests

  // it('Test 3: Less than 60% test. Add a invalid block to the Celestia Merkle Tree and check the state is not updated.', async () => {
  //   const newData = "New data json. In real life, this would be a block commitment.";

  //   // Generate Celestia Tree
  //   const celestiaTree = new MerkleTree(MAX_CELESTIA_MERKLE_TREE_HEIGHT);
  //   for (let i = 0; i < celestiaData.length; i++)
  //     celestiaTree.setLeaf(BigInt(i), Poseidon.hash([Field(stringToBigInt(celestiaData[i]))]));

  //   // Push to Celestia
  //   const height = pushToCelestia(newData);

  //   // Create the new block
  //   const newBlock = new Block(
  //     Field(stringToBigInt(newData)),
  //     Field(height),
  //     new CelestiaMerkleWitnessClass(celestiaTree.getWitness(BigInt(height)))
  //   );

  //   // Create the Signer Tree
  //   const signers = Array.from({ length: SIGNER_COUNT }, (_, i) => new Signer(
  //     signerPrivateKeys[i].toPublicKey(),
  //     SignerMerkleWitnessClass.empty(), // Hash does not depend on the witness, so this is fine.
  //     Field(0)
  //   ));
  //   const signerTree = new MerkleTree(MAX_SIGNER_MERKLE_TREE_HEIGHT);
  //   for (let i = 0; i < SIGNER_COUNT; i++)
  //     signerTree.setLeaf(BigInt(i), signers[i].hash());
  //   for (let i = SIGNER_COUNT; i < MAX_SIGNER_COUNT; i++)
  //     signerTree.setLeaf(BigInt(i), Signer.empty().hash());
  //   for (let i = 0; i < SIGNER_COUNT; i++) {
  //     signers[i] = new Signer(
  //       signerPrivateKeys[i].toPublicKey(),
  //       new SignerMerkleWitnessClass(signerTree.getWitness(BigInt(i))),
  //       Field(0)
  //     );
  //   }

  //   // Access the Node API: Get the singed block hash from the first 3 signers
  //   const signedBlockHash1 = signBlock(
  //     signerPrivateKeys[0],
  //     newBlock
  //   );
  //   const signedBlockHash2 = signBlock(
  //     signerPrivateKeys[1],
  //     newBlock
  //   );
  //   // Create proofs using signed data and signer information
  //   const proof1 = new BlockProof(
  //     signers[0],
  //     signedBlockHash1,
  //     Field(height)
  //   );
  //   const proof2 = new BlockProof(
  //     signers[1],
  //     signedBlockHash2,
  //     Field(height)
  //   );

  //   // Send the transaction
  //   const txn = await Mina.transaction(deployerAccount, () => {
  //     zkApp.update(
  //       newBlock,
  //       proof1,
  //       proof2,
  //       BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty()
  //     );
  //   });
  //   await txn.prove();
  //   await txn.sign([deployerKey, zkAppPrivateKey]).send();

  //   // Update local Signer tree
  //   // signerTree.setLeaf(BigInt(0), signers[0].sign().hash());
  //   // signerTree.setLeaf(BigInt(1), signers[1].sign().hash());

  //   // Check the new Celestia Merkle Tree root
  //   expect(zkApp.celestiaBlocksTree.get()).toThrow();

  //   // Check the new Signer Merkle Tree root
  //   // expect(zkApp.signersTree.get()).toEqual(signerTree.getRoot());
  // });

  // it('Test 4: Duplicate signer test. Add a invalid block to the Celestia Merkle Tree and check the state is not updated.', async () => {
  //   const newData = "New data json. In real life, this would be a block commitment.";

  //   // Generate Celestia Tree
  //   const celestiaTree = new MerkleTree(MAX_CELESTIA_MERKLE_TREE_HEIGHT);
  //   for (let i = 0; i < celestiaData.length; i++)
  //     celestiaTree.setLeaf(BigInt(i), Poseidon.hash([Field(stringToBigInt(celestiaData[i]))]));

  //   // Push to Celestia
  //   const height = pushToCelestia(newData);

  //   // Create the new block
  //   const newBlock = new Block(
  //     Field(stringToBigInt(newData)),
  //     Field(height),
  //     new CelestiaMerkleWitnessClass(celestiaTree.getWitness(BigInt(height)))
  //   );

  //   // Create the Signer Tree
  //   const signers = Array.from({ length: SIGNER_COUNT }, (_, i) => new Signer(
  //     signerPrivateKeys[i].toPublicKey(),
  //     SignerMerkleWitnessClass.empty(), // Hash does not depend on the witness, so this is fine.
  //     Field(0)
  //   ));
  //   const signerTree = new MerkleTree(MAX_SIGNER_MERKLE_TREE_HEIGHT);
  //   for (let i = 0; i < SIGNER_COUNT; i++)
  //     signerTree.setLeaf(BigInt(i), signers[i].hash());
  //   for (let i = SIGNER_COUNT; i < MAX_SIGNER_COUNT; i++)
  //     signerTree.setLeaf(BigInt(i), Signer.empty().hash());
  //   for (let i = 0; i < SIGNER_COUNT; i++) {
  //     signers[i] = new Signer(
  //       signerPrivateKeys[i].toPublicKey(),
  //       new SignerMerkleWitnessClass(signerTree.getWitness(BigInt(i))),
  //       Field(0)
  //     );
  //   }

  //   // Access the Node API: Get the singed block hash from the first 3 signers
  //   const signedBlockHash1 = signBlock(
  //     signerPrivateKeys[0],
  //     newBlock
  //   );
  //   const signedBlockHash2 = signBlock(
  //     signerPrivateKeys[1],
  //     newBlock
  //   );
  //   const signedBlockHash3 = signBlock( // Same as signedBlockHash2
  //     signerPrivateKeys[1],
  //     newBlock
  //   );
  //   // Create proofs using signed data and signer information
  //   const proof1 = new BlockProof(
  //     signers[0],
  //     signedBlockHash1,
  //     Field(height)
  //   );
  //   const proof2 = new BlockProof(
  //     signers[1],
  //     signedBlockHash2,
  //     Field(height)
  //   );
  //   const proof3 = new BlockProof(
  //     signers[2],
  //     signedBlockHash3,
  //     Field(height)
  //   );

  //   // Send the transaction
  //   const txn = await Mina.transaction(deployerAccount, () => {
  //     zkApp.update(
  //       newBlock,
  //       proof1,
  //       proof2,
  //       proof3,
  //       BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty(), BlockProof.empty()
  //     );
  //   });
  //   await txn.prove();
  //   await txn.sign([deployerKey, zkAppPrivateKey]).send();

  //   // Check the new Celestia Merkle Tree root
  //   expect(zkApp.celestiaBlocksTree.get()).toThrow();

  //   // Check the new Signer Merkle Tree root
  //   // expect(zkApp.signersTree.get()).toEqual(signerTree.getRoot());
  // });

  // it('Test 5: Add a valid signer to the Signer Merkle Tree and check the state is updated as expected.', async () => {
  //    // Create the new Signer
  //   const newSigner = new Signer(
  //     signerPrivateKeys[SIGNER_COUNT].toPublicKey(),
  //     SignerMerkleWitnessClass.empty(),
  //     Field(0)
  //   );

  //   // Create the Signer Tree
  //   const signers = Array.from({ length: SIGNER_COUNT }, (_, i) => new Signer(
  //     signerPrivateKeys[i].toPublicKey(),
  //     SignerMerkleWitnessClass.empty(), // Hash does not depend on the witness, so this is fine.
  //     Field(0)
  //   ));
  //   const signerTree = new MerkleTree(MAX_SIGNER_MERKLE_TREE_HEIGHT);
  //   for (let i = 0; i < SIGNER_COUNT; i++)
  //     signerTree.setLeaf(BigInt(i), signers[i].hash());
  //   for (let i = SIGNER_COUNT; i < MAX_SIGNER_COUNT; i++)
  //     signerTree.setLeaf(BigInt(i), Signer.empty().hash());
  //   for (let i = 0; i < SIGNER_COUNT; i++) {
  //     signers[i] = new Signer(
  //       signerPrivateKeys[i].toPublicKey(),
  //       new SignerMerkleWitnessClass(signerTree.getWitness(BigInt(i))),
  //       Field(0)
  //     );
  //   }

  //   newSigner.witness = new SignerMerkleWitnessClass(signerTree.getWitness(BigInt(SIGNER_COUNT)));

  //   // Access the Node API: Get the singed block hash from the first 3 signers
  //   const signedBlockHash1 = signSigner(
  //     signerPrivateKeys[0],
  //     newSigner
  //   );
  //   const signedBlockHash2 = signSigner(
  //     signerPrivateKeys[1],
  //     newSigner
  //   );
  //   const signedBlockHash3 = signSigner(
  //     signerPrivateKeys[2],
  //     newSigner
  //   );
  //   // Create proofs using signed data and signer information
  //   const proof1 = new SignerProof(
  //     signers[0],
  //     signedBlockHash1
  //   );
  //   const proof2 = new SignerProof(
  //     signers[1],
  //     signedBlockHash2
  //   );
  //   const proof3 = new SignerProof(
  //     signers[2],
  //     signedBlockHash3
  //   );

  //   // Send the transaction
  //   const txn = await Mina.transaction(deployerAccount, () => {
  //     zkApp.register(
  //       newSigner,
  //       proof1,
  //       proof2,
  //       proof3,
  //       SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty()
  //     );
  //   });
  //   await txn.prove();
  //   await txn.sign([deployerKey, zkAppPrivateKey]).send();

  //   // Update the Signer Merkle Tree
  //   signerTree.setLeaf(BigInt(SIGNER_COUNT), newSigner.hash());

  //   // Check the new Signer Merkle Tree root
  //   expect(zkApp.signersTree.get()).toEqual(signerTree.getRoot());
  // });

  // it('Test 6: Remove a Signer from Signer Merkle Tree and check the state is updated as expected.', async () => {
  //   // First add a new Signer to remove

  //   // Create the new Signer
  //   const newSigner = new Signer(
  //     signerPrivateKeys[SIGNER_COUNT].toPublicKey(),
  //     SignerMerkleWitnessClass.empty(),
  //     Field(0)
  //   );

  //   // Create the Signer Tree
  //   const signers = Array.from({ length: SIGNER_COUNT }, (_, i) => new Signer(
  //     signerPrivateKeys[i].toPublicKey(),
  //     SignerMerkleWitnessClass.empty(), // Hash does not depend on the witness, so this is fine.
  //     Field(0)
  //   ));
  //   const signerTree = new MerkleTree(MAX_SIGNER_MERKLE_TREE_HEIGHT);
  //   for (let i = 0; i < SIGNER_COUNT; i++)
  //     signerTree.setLeaf(BigInt(i), signers[i].hash());
  //   for (let i = SIGNER_COUNT; i < MAX_SIGNER_COUNT; i++)
  //     signerTree.setLeaf(BigInt(i), Signer.empty().hash());
  //   for (let i = 0; i < SIGNER_COUNT; i++) {
  //     signers[i] = new Signer(
  //       signerPrivateKeys[i].toPublicKey(),
  //       new SignerMerkleWitnessClass(signerTree.getWitness(BigInt(i))),
  //       Field(0)
  //     );
  //   }

  //   newSigner.witness = new SignerMerkleWitnessClass(signerTree.getWitness(BigInt(SIGNER_COUNT)));

  //   // Access the Node API: Get the singed block hash from the first 3 signers
  //   const signedBlockHash1 = signSigner(
  //     signerPrivateKeys[0],
  //     newSigner
  //   );
  //   const signedBlockHash2 = signSigner(
  //     signerPrivateKeys[1],
  //     newSigner
  //   );
  //   const signedBlockHash3 = signSigner(
  //     signerPrivateKeys[2],
  //     newSigner
  //   );
  //   // Create proofs using signed data and signer information
  //   const proof1 = new SignerProof(
  //     signers[0],
  //     signedBlockHash1
  //   );
  //   const proof2 = new SignerProof(
  //     signers[1],
  //     signedBlockHash2
  //   );
  //   const proof3 = new SignerProof(
  //     signers[2],
  //     signedBlockHash3
  //   );

  //   // Send the transaction
  //   const txn = await Mina.transaction(deployerAccount, () => {
  //     zkApp.register(
  //       newSigner,
  //       proof1,
  //       proof2,
  //       proof3,
  //       SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty()
  //     );
  //   });
  //   await txn.prove();
  //   await txn.sign([deployerKey, zkAppPrivateKey]).send();

  //   // Update the Signer Merkle Tree
  //   signerTree.setLeaf(BigInt(SIGNER_COUNT), newSigner.hash());
  //   newSigner.witness = new SignerMerkleWitnessClass(signerTree.getWitness(BigInt(SIGNER_COUNT)));

  //   // Check the new Signer Merkle Tree root
  //   expect(zkApp.signersTree.get()).toEqual(signerTree.getRoot());
  //   expect(zkApp.signerCount.get()).toEqual(Field(SIGNER_COUNT + 1));

  //   // Now remove the first Signer

  //   // Access the Node API: Get the singed block hash from the first 3 signers
  //   const remove_signedBlockHash1 = signSigner(
  //     signerPrivateKeys[SIGNER_COUNT],
  //     signers[0]
  //   );
  //   const remove_signedBlockHash2 = signSigner(
  //     signerPrivateKeys[1],
  //     signers[0]
  //   );
  //   const remove_signedBlockHash3 = signSigner(
  //     signerPrivateKeys[2],
  //     signers[0]
  //   );
  //   // Create proofs using signed data and signer information
  //   const remove_proof1 = new SignerProof(
  //     newSigner,
  //     remove_signedBlockHash1
  //   );
  //   const remove_proof2 = new SignerProof(
  //     signers[1],
  //     remove_signedBlockHash2
  //   );
  //   const remove_proof3 = new SignerProof(
  //     signers[2],
  //     remove_signedBlockHash3
  //   );

  //   // Send the transaction
  //   const txn2 = await Mina.transaction(deployerAccount, () => {
  //     zkApp.deregister(
  //       signers[0],
  //       remove_proof1,
  //       remove_proof2,
  //       remove_proof3,
  //       SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty(), SignerProof.empty()
  //     );
  //   });
  //   await txn2.prove();
  //   await txn2.sign([deployerKey, zkAppPrivateKey]).send();

  //   // Update local Signer tree
  //   signerTree.setLeaf(BigInt(0), Signer.empty().hash());

  //   // Check the new Celestia Merkle Tree root
  //   expect(zkApp.signersTree.get()).toEqual(signerTree.getRoot());
  //   expect(zkApp.signerCount.get()).toEqual(Field(SIGNER_COUNT));

  //   // Check the new Signer Merkle Tree root
  //   // expect(zkApp.signersTree.get()).toEqual(signerTree.getRoot());
  // });
});
