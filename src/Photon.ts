import {
  Field,
  method,
  MerkleTree,
  MerkleWitness,
  Signature,
  SmartContract,
  state,
  State,
  PublicKey,
  Struct,
  Bool,
  Permissions,
  Poseidon,
  Circuit,
  Provable,
  DeployArgs
} from 'snarkyjs';

const EMPTY_SIGNATURE = '0x0000000';
const INITIAL_HASH = Field(0);
const MAX_MERKLE_TREE_HEIGHT = 32; // Max ~10^9 data points are supported
const MAX_SIGNER_COUNT = 200; // Max 200 signers are supported

export class MerkleWitnessClass extends MerkleWitness(MAX_MERKLE_TREE_HEIGHT) {
  static empty(): MerkleWitnessClass {
    return new MerkleWitnessClass([]);
  };
};

export class Verifier extends Struct({
  signerKey: PublicKey,
  signerWitness: MerkleWitnessClass,
  signedDataPoint: Signature
}) {
  constructor(
    signerKey: PublicKey,
    signerWitness: MerkleWitnessClass,
    signedDataPoint: Signature
  ) {
    super({
      signerKey,
      signerWitness,
      signedDataPoint
    });
    this.signerKey = signerKey;
    this.signerWitness = signerWitness;
    this.signedDataPoint = signedDataPoint;
  };

  static empty(): Verifier {
    return new Verifier(
      PublicKey.empty(),
      MerkleWitnessClass.empty(),
      Signature.fromBase58(EMPTY_SIGNATURE)
    );
  };

  isEmpty(): Bool {
    return this.signerKey.isEmpty();
  };

  check(
    root: Field
  ) {
    const node = Poseidon.hash(this.signerKey.toFields());
    root.assertEquals(this.signerWitness.calculateRoot(node));
  };

  verify(
    messageHash: Field
  ) {
    this.signedDataPoint.verify(
      this.signerKey,
      messageHash.toFields()
    ).assertEquals(Bool(true));
  };
};

function fillWithEmptyVerifiers(
  [...verifiers]: Verifier[]
): Verifier[] {
  const emptyVerifier = Verifier.empty();
  for (let i = verifiers.length; i < MAX_SIGNER_COUNT; i++)
    verifiers[i] = emptyVerifier;
  return verifiers;
};

export class VerifierList extends Struct({
  verifiers: Array.from({ length: MAX_SIGNER_COUNT }, () => Verifier)
}) {
  constructor(
    verifiers: Verifier[]
  ) {
    super({
      verifiers
    });
    this.verifiers = verifiers;
  };

  empty(): VerifierList {
    return new VerifierList([]);
  };

  verify(
    messageHash: Field
  ): Field {
    for (let i = 0; i < this.verifiers.length; i++) {
      this.verifiers[i].verify(messageHash);
    };

    return Field(1);
  };
}

export class Photon extends SmartContract {
  @state(Field) celestiaRootHash = State<Field>(); // Merkle root hash of data points on Celestia
  @state(Field) signerRootHash = State<Field>(); // Merkle root hash of public keys of signer nodes of Photon

  init() {
    super.init();
    this.celestiaRootHash.set(INITIAL_HASH);
    this.signerRootHash.set(INITIAL_HASH);
  };

  @method updateCelestiaData(
    newCelestiaDataPointHash: Field, // A data point can be represented as an array of Field elements
    newSignedCelestiaDataPointHashVerifierList: Verifier[], // The verifier list of signed data points with the signer key
    dataPointHashMerkleWitnessClass: MerkleWitnessClass, // The list of Merkle witnesses of the signers of the new data point
  ) {
    for (let i = 0; i < newSignedCelestiaDataPointHashVerifierList.length; i++) {
      newSignedCelestiaDataPointHashVerifierList[i].check(this.signerRootHash.get()); // Check that the signer is a valid signer of Photon
      newSignedCelestiaDataPointHashVerifierList[i].verify(newCelestiaDataPointHash); // Verify the signature of the data point
    }

    const filledVerifierList = fillWithEmptyVerifiers(newSignedCelestiaDataPointHashVerifierList);
    let signerCount = Field(0);
    let verifierIsNotEmpty = Bool(true);

    for (let i = 0; i < MAX_SIGNER_COUNT; i++) {
      verifierIsNotEmpty = Bool.and(verifierIsNotEmpty, filledVerifierList[i].isEmpty().not());
      signerCount = signerCount.add(Provable.if(verifierIsNotEmpty, Field(1), Field(0)));
    }

    signerCount.mul(Field(10)).assertGreaterThanOrEqual(Field(MAX_SIGNER_COUNT * 6)); // More than 60% of signers must sign the data point

    this.celestiaRootHash.assertEquals(dataPointHashMerkleWitnessClass.calculateRoot(Field(INITIAL_HASH)));

    const newCelestiaRootHash = dataPointHashMerkleWitnessClass.calculateRoot(newCelestiaDataPointHash);
    this.celestiaRootHash.set(newCelestiaRootHash);
  };

  @method addSigner(
    newSignerKeyHash: Field,
    newSignerKeyHashVerifierList: Verifier[],
    newSignerKeyMerkleWitnessClass: MerkleWitnessClass
  ) {
    for (let i = 0; i < newSignerKeyHashVerifierList.length; i++) {
      newSignerKeyHashVerifierList[i].check(this.signerRootHash.get());
      newSignerKeyHashVerifierList[i].verify(newSignerKeyHash);
    }

    const filledVerifierList = fillWithEmptyVerifiers(newSignerKeyHashVerifierList);
    let signerCount = Field(0);
    let verifierIsNotEmpty = Bool(true);

    for (let i = 0; i < MAX_SIGNER_COUNT; i++) {
      verifierIsNotEmpty = Bool.and(verifierIsNotEmpty, filledVerifierList[i].isEmpty().not());
      signerCount = signerCount.add(Provable.if(verifierIsNotEmpty, Field(1), Field(0)));
    }

    signerCount.mul(Field(10)).assertGreaterThanOrEqual(Field(MAX_SIGNER_COUNT * 6)); // More than 60% of signers must sign the data point

    const newSignerRootHash = newSignerKeyMerkleWitnessClass.calculateRoot(newSignerKeyHash);
    this.signerRootHash.set(newSignerRootHash);
  }
}
