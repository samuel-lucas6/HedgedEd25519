/*
    HedgedEd25519: Hedged signatures for protection against fault attacks.
    Copyright (c) 2022 Samuel Lucas
    
    Permission is hereby granted, free of charge, to any person obtaining a copy of
    this software and associated documentation files (the "Software"), to deal in
    the Software without restriction, including without limitation the rights to
    use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
    the Software, and to permit persons to whom the Software is furnished to do so,
    subject to the following conditions:
    
    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.
    
    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

using Geralt;

namespace HedgedEd25519DotNet;

public static class HedgedEd25519
{
    public const int PublicKeySize = Ed25519.PublicKeySize;
    public const int PrivateKeySize = Ed25519.PrivateKeySize;
    public const int NonceSize = Ed25519.SeedSize;
    public const int SignatureSize = Ed25519.SignatureSize + NonceSize;

    public static void GenerateKeyPair(Span<byte> publicKey, Span<byte> privateKey) => Ed25519.GenerateKeyPair(publicKey, privateKey);

    public static void ComputePublicKey(Span<byte> publicKey, ReadOnlySpan<byte> privateKey) => Ed25519.ComputePublicKey(publicKey, privateKey);

    public static void Sign(Span<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> privateKey)
    {
        Validation.EqualToSize(nameof(signature), signature.Length, SignatureSize);
        Validation.EqualToSize(nameof(privateKey), privateKey.Length, PrivateKeySize);
        Span<byte> nonce = stackalloc byte[NonceSize];
        SecureRandom.Fill(nonce);
        Span<byte> hedged = new byte[nonce.Length + message.Length];
        Spans.Concat(hedged, nonce, message);
        Ed25519.Sign(signature[..^nonce.Length], hedged, privateKey);
        nonce.CopyTo(signature[^nonce.Length..]);
    }

    public static bool Verify(ReadOnlySpan<byte> signature, ReadOnlySpan<byte> message, ReadOnlySpan<byte> publicKey)
    {
        Validation.EqualToSize(nameof(signature), signature.Length, SignatureSize);
        Validation.EqualToSize(nameof(publicKey), publicKey.Length, PublicKeySize);
        ReadOnlySpan<byte> nonce = signature[^NonceSize..];
        Span<byte> hedged = new byte[nonce.Length + message.Length];
        Spans.Concat(hedged, nonce, message);
        return Ed25519.Verify(signature[..^nonce.Length], hedged, publicKey);
    }
}