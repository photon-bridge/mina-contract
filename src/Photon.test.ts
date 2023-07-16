import { Photon } from './Photon';
import { Bool, Mina, PrivateKey, PublicKey, AccountUpdate } from 'snarkyjs';

let proofsEnabled = false;

describe('Test', () => {
  let deployerAccount: PublicKey,
    deployerKey: PrivateKey,
    senderAccount: PublicKey,
    senderKey: PrivateKey,
    zkAppAddress: PublicKey,
    zkAppPrivateKey: PrivateKey,
    zkApp: Photon;

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

    await localDeploy();
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

  // it('Test 1:')

  // it('Photon 1: Absolute Value - CircuitNumber.prototype.abs()', async () => {
  //   const txn = await Mina.transaction(deployerAccount, () => {
  //     zkApp.abs();
  //   });
  //   await txn.prove();
  //   await txn.sign([deployerKey, zkAppPrivateKey]).send();

  //   const result = zkApp.get();

  //   expect(result.valueOf()).toEqual(Math.abs(number1.valueOf()));
  //   console.log(`Photon 1 Passed: Absolute Value (${number1} -> ${result.valueOf()})`);
  // });

});
