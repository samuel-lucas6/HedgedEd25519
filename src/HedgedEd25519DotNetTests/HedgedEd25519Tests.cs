using System.Text;
using HedgedEd25519DotNet;
using Microsoft.VisualStudio.TestTools.UnitTesting;

namespace HedgedEd25519DotNetTests;

[TestClass]
public class HedgedEd25519Tests
{
    [TestMethod]
    public void ThoroughTest()
    {
        Span<byte> message = Encoding.UTF8.GetBytes("Hope clouds observation.");
        Span<byte> publicKey = stackalloc byte[HedgedEd25519.PublicKeySize], privateKey = stackalloc byte[HedgedEd25519.PrivateKeySize];
        HedgedEd25519.GenerateKeyPair(publicKey, privateKey);

        Span<byte> pk = stackalloc byte[HedgedEd25519.PublicKeySize];
        HedgedEd25519.ComputePublicKey(pk, privateKey);
        Assert.IsTrue(pk.SequenceEqual(publicKey));
        
        Span<byte> signature1 = stackalloc byte[HedgedEd25519.SignatureSize];
        HedgedEd25519.Sign(signature1, message, privateKey);
        Span<byte> signature2 = stackalloc byte[HedgedEd25519.SignatureSize];
        HedgedEd25519.Sign(signature2, message, privateKey);
        Assert.IsFalse(signature1.SequenceEqual(signature2));
        
        bool valid = HedgedEd25519.Verify(signature1, message, publicKey);
        Assert.IsTrue(valid);
        valid = HedgedEd25519.Verify(signature2, message, publicKey);
        Assert.IsTrue(valid);

        signature1[^1]++;
        valid = HedgedEd25519.Verify(signature1, message, publicKey);
        Assert.IsFalse(valid);

        message[^1]++;
        valid = HedgedEd25519.Verify(signature2, message, publicKey);
        Assert.IsFalse(valid);
    }
}