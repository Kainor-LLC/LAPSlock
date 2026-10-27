// HPKE, RFC 9180, the one suite the TenantKeep relay uses: DHKEM(P-256, HKDF-SHA256),
// HKDF-SHA256, AES-256-GCM, in base and authenticated modes. .NET has ECDH, HKDF and
// AES-GCM but no HPKE type, so this is the RFC written out, checked against the CFRG test
// vectors (relay/sender/Test-Hpke.ps1) and against Apple's CryptoKit, which opens what this
// seals. Loaded into PowerShell with Add-Type by TenantKeepRelaySender.ps1.
//
// Only sealing is needed by the sender; Open exists so the tests can round-trip.
using System;
using System.Security.Cryptography;
using System.Text;

namespace TenantKeep.Relay
{
    public sealed class HpkeContext
    {
        public byte[] Key;
        public byte[] BaseNonce;
        public ulong Sequence;
        public byte[] Enc;

        byte[] Nonce()
        {
            var nonce = (byte[])BaseNonce.Clone();
            for (int i = 0; i < 8; i++) nonce[nonce.Length - 1 - i] ^= (byte)(Sequence >> (8 * i));
            return nonce;
        }

        public byte[] Seal(byte[] aad, byte[] plaintext)
        {
            var ct = new byte[plaintext.Length];
            var tag = new byte[16];
            using (var gcm = new AesGcm(Key, 16)) gcm.Encrypt(Nonce(), plaintext, ct, tag, aad);
            Sequence++;
            var output = new byte[ct.Length + 16];
            Buffer.BlockCopy(ct, 0, output, 0, ct.Length);
            Buffer.BlockCopy(tag, 0, output, ct.Length, 16);
            return output;
        }

        public byte[] Open(byte[] aad, byte[] ciphertext)
        {
            var ct = new byte[ciphertext.Length - 16];
            var tag = new byte[16];
            Buffer.BlockCopy(ciphertext, 0, ct, 0, ct.Length);
            Buffer.BlockCopy(ciphertext, ct.Length, tag, 0, 16);
            var pt = new byte[ct.Length];
            using (var gcm = new AesGcm(Key, 16)) gcm.Decrypt(Nonce(), ct, tag, pt, aad);
            Sequence++;
            return pt;
        }
    }

    public static class Hpke
    {
        public const ushort KemId = 0x0010, KdfId = 0x0001;
        public const byte ModeBase = 0x00, ModeAuth = 0x02;

        static byte[] I2Osp(int value, int length)
        {
            var b = new byte[length];
            for (int i = 0; i < length; i++) b[length - 1 - i] = (byte)(value >> (8 * i));
            return b;
        }

        static byte[] Concat(params byte[][] parts)
        {
            int n = 0; foreach (var p in parts) n += p.Length;
            var o = new byte[n]; int at = 0;
            foreach (var p in parts) { Buffer.BlockCopy(p, 0, o, at, p.Length); at += p.Length; }
            return o;
        }

        static readonly byte[] Version = Encoding.ASCII.GetBytes("HPKE-v1");

        static byte[] LabeledExtract(byte[] suiteId, byte[] salt, string label, byte[] ikm) =>
            HKDF.Extract(HashAlgorithmName.SHA256, Concat(Version, suiteId, Encoding.ASCII.GetBytes(label), ikm), salt);

        static byte[] LabeledExpand(byte[] suiteId, byte[] prk, string label, byte[] info, int length) =>
            HKDF.Expand(HashAlgorithmName.SHA256, prk, length, Concat(I2Osp(length, 2), Version, suiteId, Encoding.ASCII.GetBytes(label), info));

        static byte[] KemSuite => Concat(Encoding.ASCII.GetBytes("KEM"), I2Osp(KemId, 2));

        static byte[] HpkeSuite(ushort aeadId) => Concat(Encoding.ASCII.GetBytes("HPKE"), I2Osp(KemId, 2), I2Osp(KdfId, 2), I2Osp(aeadId, 2));

        static int KeyLength(ushort aeadId) => aeadId == 0x0001 ? 16 : aeadId == 0x0002 ? 32 : throw new ArgumentException("AES-GCM only");

        /// A P-256 key from a 65-byte uncompressed point, optionally with its private scalar.
        public static ECDiffieHellman Key(byte[] publicUncompressed, byte[] privateScalar = null)
        {
            if (publicUncompressed == null || publicUncompressed.Length != 65 || publicUncompressed[0] != 0x04)
                throw new ArgumentException("expected a 65-byte uncompressed P-256 point");
            var p = new ECParameters
            {
                Curve = ECCurve.NamedCurves.nistP256,
                Q = new ECPoint { X = publicUncompressed[1..33], Y = publicUncompressed[33..65] },
                D = privateScalar
            };
            return ECDiffieHellman.Create(p);
        }

        public static byte[] PublicBytes(ECDiffieHellman key)
        {
            var q = key.ExportParameters(false).Q;
            return Concat(new byte[] { 0x04 }, q.X, q.Y);
        }

        static byte[] Dh(ECDiffieHellman priv, ECDiffieHellman pub) => priv.DeriveRawSecretAgreement(pub.PublicKey);

        static byte[] ExtractAndExpand(byte[] dh, byte[] kemContext)
        {
            var prk = LabeledExtract(KemSuite, Array.Empty<byte>(), "eae_prk", dh);
            return LabeledExpand(KemSuite, prk, "shared_secret", kemContext, 32);
        }

        static HpkeContext KeySchedule(byte mode, byte[] sharedSecret, byte[] info, ushort aeadId, byte[] enc)
        {
            var suite = HpkeSuite(aeadId);
            var pskIdHash = LabeledExtract(suite, Array.Empty<byte>(), "psk_id_hash", Array.Empty<byte>());
            var infoHash = LabeledExtract(suite, Array.Empty<byte>(), "info_hash", info);
            var context = Concat(new[] { mode }, pskIdHash, infoHash);
            var secret = LabeledExtract(suite, sharedSecret, "secret", Array.Empty<byte>());
            return new HpkeContext
            {
                Key = LabeledExpand(suite, secret, "key", context, KeyLength(aeadId)),
                BaseNonce = LabeledExpand(suite, secret, "base_nonce", context, 12),
                Sequence = 0,
                Enc = enc
            };
        }

        /// Sender, authenticated mode. `ephemeral` is for test vectors only; pass null.
        public static HpkeContext SetupAuthSender(byte[] recipientPublic, ECDiffieHellman sender, byte[] info, ushort aeadId, ECDiffieHellman ephemeral = null)
        {
            using var pkR = Key(recipientPublic);
            var skE = ephemeral ?? ECDiffieHellman.Create(ECCurve.NamedCurves.nistP256);
            var enc = PublicBytes(skE);
            var dh = Concat(Dh(skE, pkR), Dh(sender, pkR));
            var kemContext = Concat(enc, recipientPublic, PublicBytes(sender));
            return KeySchedule(ModeAuth, ExtractAndExpand(dh, kemContext), info, aeadId, enc);
        }

        /// Recipient, authenticated mode, for the tests.
        public static HpkeContext SetupAuthRecipient(byte[] enc, ECDiffieHellman recipient, byte[] senderPublic, byte[] info, ushort aeadId)
        {
            using var pkE = Key(enc);
            using var pkS = Key(senderPublic);
            var dh = Concat(Dh(recipient, pkE), Dh(recipient, pkS));
            var kemContext = Concat(enc, PublicBytes(recipient), senderPublic);
            return KeySchedule(ModeAuth, ExtractAndExpand(dh, kemContext), info, aeadId, enc);
        }
    }
}
