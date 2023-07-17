import {
  Bool,
  Field,
  MerkleTree,
  MerkleWitness,
  method,
  Poseidon,
  Provable,
  PublicKey,
  Reducer,
  Signature,
  SmartContract,
  state,
  State,
  Struct
} from 'snarkyjs';

const EMPTY_PUBLIC_KEY = "B62qrhCn7DK2b4pzbJCAxxBN1cyVAyLgN2JZDe67EV76oneJbyiCfDh";
const EMPTY_SIGNATURE = "7mXRxyZzn511bfSEnPyWj5jqMBYssxAhTwa81Zb1p4bc4KANxMyJ9CsfHUZ64wTE28kbBZ6UcCWuotQk4TxuYdnQvZcJXKdC"; // TODO: Make this an empty string, this is a current valid signature right now for a test private key. // A base-58 encoded empty signature to initalize an empty BlockProof.

const EMPTY_HASH = Field(0); // An empty hash to initialize an empty Merkle tree.
const MAX_CELESTIA_MERKLE_TREE_HEIGHT = 17; // The Celestia merkle tree can hold at most 2^32 (4294967296) block hashes.
const MAX_BLOCK_COUNT = 65536; // Max 65536 blocks are supported. This number can be increased if needed, but do not forget to change the MAX_CELESTIA_MERKLE_TREE_HEIGHT as well.
const MAX_SIGNER_MERKLE_TREE_HEIGHT = 9; // The Signer merkle tree can hold at most 2^10 (1024) signers.
const MAX_SIGNER_COUNT = 200; // Max 200 signers are supported. This number can be increased if needed, but do not forget to change the MAX_SIGNER_MERKLE_TREE_HEIGHT as well.

const celestiaEmptyTree = new MerkleTree(MAX_CELESTIA_MERKLE_TREE_HEIGHT);
const signerEmptyTree = new MerkleTree(MAX_SIGNER_MERKLE_TREE_HEIGHT);

// The contract has two CelestiaMerkleWitnessClass since Celestia and Signer merkle trees have very different heights.
export class CelestiaMerkleWitnessClass extends MerkleWitness(MAX_CELESTIA_MERKLE_TREE_HEIGHT) {
  // Generate an empty CelestiaMerkleWitnessClass
  static empty(): CelestiaMerkleWitnessClass {
    return new CelestiaMerkleWitnessClass(celestiaEmptyTree.getWitness(0n));
  };
};
export class SignerMerkleWitnessClass extends MerkleWitness(MAX_SIGNER_MERKLE_TREE_HEIGHT) {
  // Generate an empty SignerMerkleWitnessClass
  static empty(): SignerMerkleWitnessClass {
    return new SignerMerkleWitnessClass(signerEmptyTree.getWitness(0n));
  };
};

// Signer holds the information generated by a `Signer` to verify a block.
// A `Signer` is a 3rd party node that signs a block hash on Celestia upon request.
// The contract keeps track of `signingCount` of each `Signer` node as an incentive to sign the block hash.
export class Signer extends Struct({
  key: PublicKey, // The public key of the `Signer` node.
  witness: SignerMerkleWitnessClass, // The Merkle witness of the `Signer` node to verify the public key belongs to `signersTree` state.
  signingCount: Field // The number of times this `Signer` node has signed a block hash on Celestia.
}) {
  constructor(
    key: PublicKey,
    witness: SignerMerkleWitnessClass,
    signingCount: Field
  ) {
    super({
      key,
      witness,
      signingCount
    });
    this.key = key;
    this.witness = witness;
    this.signingCount = signingCount;
  };

  static empty() {
    return new Signer(
      PublicKey.fromBase58(EMPTY_PUBLIC_KEY),
      SignerMerkleWitnessClass.empty(),
      Field(0)
    );
  };

  // Return a Bool representing if this Signer belongs to the given merkle tree root hash.
  check(
    root: Field
  ): Bool {
    return root.equals(
      this.witness.calculateRoot(this.hash())
    );
  };

  // Return an hash for this Signer.
  hash(): Field {
    return Poseidon.hash(this.key.toFields().concat([this.signingCount]));
  };

  // Return a Bool representing if this Signer is empty.
  isEmpty(): Bool {
    return this.key.equals(PublicKey.fromBase58(EMPTY_PUBLIC_KEY));
  };

  // Create & Return a new Signer with 1 more `signingCount` than this Signer.
  sign(): Signer {
    return new Signer(
      this.key,
      this.witness,
      this.signingCount.add(Field(1))
    );
  };
};

// Each `Block` on Celestia merkle tree is a hash of the block data and the height of the block.
export class Block extends Struct({
  data: Field, // The hash of the block data.
  height: Field, // The height of the block.
  witness: CelestiaMerkleWitnessClass // The Merkle witness of the block to verify the block hash belongs to `celestiaBlocksTree` state.
}) {
  constructor(
    data: Field,
    height: Field,
    witness: CelestiaMerkleWitnessClass
  ) {
    super({
      data,
      height,
      witness
    });
    this.data = data;
    this.height = height;
    this.witness = witness;
  };

  // Create an empty Block with dummy values
  static empty(): Block {
    return new Block(
      Field(0),
      Field(0),
      CelestiaMerkleWitnessClass.empty()
    );
  };

  // Return an hash for this Block.
  hash(): Field {
    return Poseidon.hash([this.data, this.height]);
  };
};

// BlockProof holds the information generated by a `Signer` to verify a block.
// In order to update Mina state, the user must ask at least 60% of `Signer` nodes to sign the block hash of Celestia state.
export class BlockProof extends Struct({
  signer: Signer, // The `Signer` node that signed this BlockProof
  signedBlockHash: Signature, // The signed block hash of Celestia state
  signedBlockHeight: Field // The block height of the signed block hash
}) {
  constructor(
    signer: Signer,
    signedBlockHash: Signature,
    signedBlockHeight: Field
  ) {
    super({
      signer,
      signedBlockHash,
      signedBlockHeight
    });
    this.signer = signer;
    this.signedBlockHash = signedBlockHash;
    this.signedBlockHeight = signedBlockHeight;
  };

  // Create an empty BlockProof with dummy values
  static empty(): BlockProof {
    return new BlockProof(
      Signer.empty(),
      Signature.fromBase58(EMPTY_SIGNATURE),
      Field(0)
    );
  };

  // Return a Bool representing if this BlockProof is an empty BlockProof
  isEmpty(): Bool {
    return this.signer.isEmpty();
  };

  // Return a Bool representing if this BlockProof is valid for a Block.
  verify(
    signerRoot: Field, // The merkle root hash of the Signer merkle tree to verify the `this.signer` belongs is trusted by this smart contract.
    block: Block, // The block to verify the signature of this BlockProof.
  ): Bool {
    return this.signer.check(
      signerRoot
    )
    .and(
      this.signedBlockHash.verify(
        this.signer.key,
        [block.hash()]
      )
    )
    .and(
      this.signedBlockHeight.equals(
        block.height
      )
    );
  };
};

// SignerProof holds the information generated by a `Signer` to verify a new `Signer`.
// In order to join the Mina state as a `Signer`, the new `Signer` must ask at least 60% of `Signer` nodes to sign the hash of the new `Signer`.
export class SignerProof extends Struct({
  signer: Signer, // The `Signer` node that signed this SignerProof
  signedSignerHash: Signature // The signed signer hash of Celestia state
}) {
  constructor(
    signer: Signer,
    signedSignerHash: Signature
  ) {
    super({
      signer,
      signedSignerHash
    });
    this.signer = signer;
    this.signedSignerHash = signedSignerHash;
  };

  // Create an empty SignerProof with dummy values
  static empty(): SignerProof {
    return new SignerProof(
      Signer.empty(),
      Signature.fromBase58(EMPTY_SIGNATURE)
    );
  };

  // Return a Bool representing if this SignerProof is an empty SignerProof
  isEmpty(): Bool {
    return this.signer.isEmpty();
  };

  // Return a Bool representing if this SignerProof is valid for a Signer.
  verify(
    signerRoot: Field, // The merkle root hash of the Signer merkle tree to verify the `this.signer` belongs is trusted by this smart contract.
    signer: Signer, // The `Signer` to verify the signature of this SignerProof.
  ): Bool {
    return this.signer.check(
      signerRoot
    ).and(
      this.signedSignerHash.verify(
        this.signer.key,
        signer.key.toFields().concat([signer.signingCount])
      )
    );
  };
};

// A utility function to fill the given BlockProof array with empty BlockProofs until it reaches MAX_SIGNER_COUNT
function fillWithEmptyBlockProofs(
  [...provers]: BlockProof[]
): BlockProof[]{
  const emptyProof = BlockProof.empty();

  for (let i = provers.length; i < MAX_BLOCK_COUNT; i++)
    provers[i] = emptyProof;
  return provers;
};
// A utility function to fill the given BlockProof array with empty SignerProofs until it reaches MAX_SIGNER_COUNT
function fillWithEmptySignerProofs(
  [...provers]: SignerProof[]
): SignerProof[]{
  const emptyProof = SignerProof.empty();

  for (let i = provers.length; i < MAX_SIGNER_COUNT; i++)
    provers[i] = emptyProof;
  return provers;
};

// BlockProofList holds an array of Proofs with length MAX_SIGNER_COUNT
export class BlockProofList extends Struct({
  provers: Array.from({ length: MAX_SIGNER_COUNT }, () => BlockProof)
}) {
  constructor(
    provers: BlockProof[]
  ) {
    super({
      provers
    });
    this.provers = fillWithEmptyBlockProofs(provers.splice(0, MAX_SIGNER_COUNT));
  };
};

// SignerProofList holds an array of Proofs with length MAX_SIGNER_COUNT
export class SignerProofList extends Struct({
  provers: Array.from({ length: MAX_SIGNER_COUNT }, () => SignerProof)
}) {
  constructor(
    provers: SignerProof[]
  ) {
    super({
      provers
    });
    this.provers = fillWithEmptySignerProofs(provers.splice(0, MAX_SIGNER_COUNT));
  };
};

export class Photon extends SmartContract {
  @state(Field) celestiaBlocksTree = State<Field>(); // Merkle root hash of `Block` tree on Celestia.
  @state(Field) signerCount = State<Field>(); // Number of Signers registered to the contract.
  @state(Field) signersTree = State<Field>(); // Merkle root hash of `Signer` nodes of Photon.
  @state(Field) signersTreeAccumulator = State<Field>(); // Accumulator of `Signer` nodes of Photon.

  reducer = Reducer({ actionType: Signer });

  init() {
    super.init();
    this.celestiaBlocksTree.set(EMPTY_HASH);
    this.signerCount.set(Field(0));
    this.signersTree.set(EMPTY_HASH);
    this.signersTreeAccumulator.set(Reducer.initialActionState);
  };

  // Initialize the contract with the given initial Celestia and Signer merkle tree root hashes.
  @method initialize(
    initialCelestiaRootHash: Field,
    initialSignerCount: Field,
    initialSignerRootHash: Field
  ) {
    this.celestiaBlocksTree.assertEquals(EMPTY_HASH);
    this.signerCount.assertEquals(Field(0));
    this.signersTree.assertEquals(EMPTY_HASH);

    this.celestiaBlocksTree.set(initialCelestiaRootHash);
    this.signerCount.set(initialSignerCount);
    this.signersTree.set(initialSignerRootHash);
  };

  // Update the Celestia merkle tree with the given new block hash and block height.
  @method update(
    newBlock: Block, // The new `Block` to be included in Celestia merkle tree.
    prover1: BlockProof, // The `Prover` of the first `Signer` node.
    prover2: BlockProof, // The `Prover` of the second `Signer` node.
    prover3: BlockProof, // The `Prover` of the third `Signer` node.
    prover4: BlockProof, // The `Prover` of the fourth `Signer` node.
    prover5: BlockProof, // The `Prover` of the fifth `Signer` node.
    prover6: BlockProof, // The `Prover` of the sixth `Signer` node.
    prover7: BlockProof, // The `Prover` of the seventh `Signer` node.
    prover8: BlockProof, // The `Prover` of the eighth `Signer` node.
    prover9: BlockProof, // The `Prover` of the ninth `Signer` node.
    prover10: BlockProof, // The `Prover` of the tenth `Signer` node.
    prover11: BlockProof, // The `Prover` of the eleventh `Signer` node.
    prover12: BlockProof, // The `Prover` of the twelfth `Signer` node.
    prover13: BlockProof, // The `Prover` of the thirteenth `Signer` node.
    prover14: BlockProof, // The `Prover` of the fourteenth `Signer` node.
    prover15: BlockProof, // The `Prover` of the fifteenth `Signer` node.
    prover16: BlockProof, // The `Prover` of the sixteenth `Signer` node.
    prover17: BlockProof, // The `Prover` of the seventeenth `Signer` node.
    prover18: BlockProof, // The `Prover` of the eighteenth `Signer` node.
    prover19: BlockProof, // The `Prover` of the nineteenth `Signer` node.
    prover20: BlockProof // The `Prover` of the twentieth `Signer` node.
  ) {
    this.celestiaBlocksTree.assertEquals(this.celestiaBlocksTree.get());
    this.signerCount.assertEquals(this.signerCount.get());
    this.signersTree.assertEquals(this.signersTree.get());
    this.signersTreeAccumulator.assertEquals(this.signersTreeAccumulator.get());

    const celestiaBlocksTree = this.celestiaBlocksTree.get();
    const signerCount = this.signerCount.get();
    const signersTree = this.signersTree.get();
    const signersTreeAccumulator = this.signersTreeAccumulator.get();

    const newBlockProvers = new BlockProofList([
      prover1, prover2, prover3, prover4, prover5, prover6, prover7, prover8, prover9, prover10, prover11, prover12, prover13, prover14, prover15, prover16, prover17, prover18, prover19, prover20
    ]);

    signerCount.equals(Field(0)).assertEquals(Bool(false)); // There is at least 1 signer

    let allValid = Bool(true);
    let currSignerCount = Field(0); // Number of Signers signed this proof.

    for (let i = 0; i < MAX_SIGNER_COUNT; i++) {
      const prover = newBlockProvers.provers[i];

      allValid = Bool.and(
        allValid,
        Bool.or(
          prover.isEmpty(),
          prover.verify(
            signersTree,
            newBlock
          )
        )
      );

      currSignerCount = currSignerCount.add(
        Provable.if(
          prover.isEmpty(),
          Field(0),
          Field(1)
        )
      );

      // this.reducer.dispatch(prover.signer); // Update the signer state with the new `signingCount`.
    };

    allValid.assertEquals(Bool(true));
    currSignerCount.mul(Field(10)).assertGreaterThanOrEqual(signerCount.mul(Field(6))); // More than 60% of signers should have signed the `BlockProof`.

    // const { state: newSignersTree, actionState: newSignersTreeAccumulator } = this.reducer.reduce(
    //   this.reducer.getActions({ fromActionState: signersTreeAccumulator }), // The current accumulator state.
    //   Field, // State type - merkle root
    //   (state: Field, action: Signer) => {
    //     state.assertEquals(action.witness.calculateRoot(action.hash())); // This makes sure that each Signer signed only once inside the `ProverList`.
    //     action = action.sign(); // Add 1 signing to the signer.
    //     return action.witness.calculateRoot(action.hash()); // Update the merkle tree state.
    //   },
    //   { state: signersTree, actionState: signersTreeAccumulator }
    // );

    const newCelestiaBlocksTree = newBlock.witness.calculateRoot(newBlock.hash()); // The new Celestia merkle tree root hash.

    this.celestiaBlocksTree.set(newCelestiaBlocksTree);
    // this.signersTree.set(newSignersTree);
    // this.signersTreeAccumulator.set(newSignersTreeAccumulator);
  };

  // Register a new Signer node to the contract.
  @method register(
    newSigner: Signer, // The new `Signer` to add to the contract.
    newSignerProvers: SignerProofList // The `Prover` list of the new `Signer` node.
  ) {
    newSigner.signingCount.assertEquals(Field(0)); // The new Signer should have 0 `signingCount`.

    this.signerCount.assertEquals(this.signerCount.get());
    this.signersTree.assertEquals(this.signersTree.get());
    this.signersTreeAccumulator.assertEquals(this.signersTreeAccumulator.get());

    const signerCount = this.signerCount.get();
    const signersTree = this.signersTree.get();
    const signersTreeAccumulator = this.signersTreeAccumulator.get();

    const oldSignersTree = newSigner.witness.calculateRoot(Block.empty().hash()); // The Block should have been empty on the previous Celestia merkle tree.
    signersTree.assertEquals(oldSignersTree); // Check that the previous Celestia merkle tree root hash is correct.

    let currSignerCount = Field(0); // Number of Signers signed this proof.

    for (let i = 0; i < MAX_SIGNER_COUNT; i++) {
      const prover = newSignerProvers.provers[i];

      Bool.or(
        prover.isEmpty(),
        prover.verify(
          signersTree,
          newSigner
        )
      ).assertEquals(Bool(true)); // Check that the prover is either empty or valid.

      currSignerCount.add(Provable.if(
        prover.isEmpty(),
        Field(0),
        Field(1)
      ));

      this.reducer.dispatch(prover.signer); // Update the signer state with the new `signingCount`.
    };

    currSignerCount.mul(Field(10)).assertGreaterThanOrEqual(signerCount.mul(Field(6))); // More than 60% of signers should have signed the `BlockProof`.

    this.reducer.dispatch(newSigner); // The newSigner is also registered with the reducer 
    // NOTE: As the newSigner is added with the Reducer logic, it starts with 1 `signingCount` already. You may think that as a bonus, instead of a coding trick :)

    let { state: newSignersTree, actionState: newSignersTreeAccumulator } = this.reducer.reduce(
      this.reducer.getActions({ fromActionState: signersTreeAccumulator }), // The current accumulator state.
      Field, // State type - merkle root.
      (state: Field, action: Signer) => {
        state.assertEquals(action.witness.calculateRoot(action.hash())); // This makes sure that each Signer signed only once inside the `ProverList`.
        action = action.sign(); // Add 1 signing to the signer.
        return action.witness.calculateRoot(action.hash()); // Update the merkle tree state.
      },
      { state: signersTree, actionState: signersTreeAccumulator }
    );

    this.signerCount.set(signerCount.add(Field(1))); // There is a new signer now.
    this.signersTree.set(newSignersTree);
    this.signersTreeAccumulator.set(newSignersTreeAccumulator);
  };
};
