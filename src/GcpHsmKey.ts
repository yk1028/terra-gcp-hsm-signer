import { Key, SimplePublicKey } from '@terra-money/terra.js';
import { GcpHsmSigner } from './GcpHsmSigner';
import { SHA256, Word32Array } from 'jscrypto';

export class GcpHsmKey extends Key {

  constructor(private signer: GcpHsmSigner, publicKey: Uint8Array) {
    super(new SimplePublicKey(Buffer.from(publicKey).toString('base64')));
  }

  public async sign(payload: Buffer): Promise<Buffer> {
    const hash = Buffer.from(
      SHA256.hash(new Word32Array(payload)).toString(),
      'hex'
    );
    return this.signer.sign(hash);
  }
}