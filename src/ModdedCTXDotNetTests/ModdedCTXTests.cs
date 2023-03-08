using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using ModdedCTXDotNet;

namespace ModdedCTXDotNetTests;

[TestClass]
public class ModdedCTXTests
{
    // Based on https://github.com/brycx/CTXTestVectors/blob/main/CTXTestVectors/TestFiles/ctx_xchacha20_poly1305_blake2b_256.json
    public static IEnumerable<object[]> TestVectors()
    {
        // Everything
        yield return new object[]
        {
            "ff347358e665692233d5a72217be55df8edabe95a9f9194297c2fef50b53fd2acc09fdb2d367799d765f7b34d490ba0d07ac21b957b1c73f7b5d554609",
            "48656c6c6f2c20776f726c6421",
            "89eb0d6a8a691dae2cd15ed0",
            "89eb0d6a8a691dae2cd15ed0369931ce0a949ecafa5c3f93f8121833646e15c3",
            "4164646974696f6e616c2064617461"
        };
        // Empty associated data
        yield return new object[]
        {
            "32940aaf4f2162781e802ba23643e1022af692b227f0a519b34b33301e44586356c920919071e715f86186ee8431bd7f2cb906607989a46924393f1de2",
            "48656c6c6f2c20776f726c6421",
            "ad83f02749cb1d750f4659a1",
            "4e8c71d217b0fec6382063f9e7615d4905131244f389fb5fd994ee354daac0f7",
            ""
        };
        // Empty plaintext
        yield return new object[]
        {
            "121b9128d79c334ac8695167f396c788675b410b5b14c5d21d1ccaad816698bdc2adcd45a70703c4b1dfad70175419f5",
            "",
            "1d33723b61107f0b6aca4e03",
            "3a4c0005c8e42599987ac76a471faecbabef25acd9be24f37ed2ae5e9ac11272",
            "4164646974696f6e616c2064617461"
        };
        // Empty plaintext and associated data
        yield return new object[]
        {
            "0757e5bd48d6c4445bcd218fa62051355d482e5c03fa2fb71cb470e176eace86cd7bafcd0db619ff4158253abe3490eb",
            "",
            "9293f234f3a2fb681a79d5eb",
            "0dd43c54c150276fd00c2168a583c3c880d43476005284fa88c2dfa12fd38499",
            ""
        };
    }
    
    public static IEnumerable<object[]> TamperedTestVectors()
    {
        // Wrong key
        yield return new object[]
        {
            "ff347358e665692233d5a72217be55df8edabe95a9f9194297c2fef50b53fd2acc09fdb2d367799d765f7b34d490ba0d07ac21b957b1c73f7b5d554609",
            "48656c6c6f2c20776f726c6421",
            "89eb0d6a8a691dae2cd15ed0",
            "99eb0d6a8a691dae2cd15ed0369931ce0a949ecafa5c3f93f8121833646e15c3",
            "4164646974696f6e616c2064617461"
        };
        // Wrong nonce
        yield return new object[]
        {
            "ff347358e665692233d5a72217be55df8edabe95a9f9194297c2fef50b53fd2acc09fdb2d367799d765f7b34d490ba0d07ac21b957b1c73f7b5d554609",
            "48656c6c6f2c20776f726c6421",
            "99eb0d6a8a691dae2cd15ed0",
            "89eb0d6a8a691dae2cd15ed0369931ce0a949ecafa5c3f93f8121833646e15c3",
            "4164646974696f6e616c2064617461"
        };
        // Wrong associated data
        yield return new object[]
        {
            "ff347358e665692233d5a72217be55df8edabe95a9f9194297c2fef50b53fd2acc09fdb2d367799d765f7b34d490ba0d07ac21b957b1c73f7b5d554609",
            "48656c6c6f2c20776f726c6421",
            "89eb0d6a8a691dae2cd15ed0",
            "89eb0d6a8a691dae2cd15ed0369931ce0a949ecafa5c3f93f8121833646e15c3",
            "5164646974696f6e616c2064617461"
        };
        // Wrong commitment
        yield return new object[]
        {
            "1f347358e665692233d5a72217be55df8edabe95a9f9194297c2fef50b53fd2acc09fdb2d367799d765f7b34d490ba0d07ac21b957b1c73f7b5d554609",
            "48656c6c6f2c20776f726c6421",
            "89eb0d6a8a691dae2cd15ed0",
            "89eb0d6a8a691dae2cd15ed0369931ce0a949ecafa5c3f93f8121833646e15c3",
            "4164646974696f6e616c2064617461"
        };
        // Wrong ciphertext
        yield return new object[]
        {
            "ff347358e665692233d5a72217be55df8edabe95a9f9194297c2fef50b53fd2acc09fdb2d367799d765f7b34d590ba0d07ac21b957b1c73f7b5d554609",
            "48656c6c6f2c20776f726c6421",
            "89eb0d6a8a691dae2cd15ed0",
            "89eb0d6a8a691dae2cd15ed0369931ce0a949ecafa5c3f93f8121833646e15c3",
            "4164646974696f6e616c2064617461"
        };
        // Wrong tag
        yield return new object[]
        {
            "ff347358e665692233d5a72217be55df8edabe95a9f9194297c2fef50b53fd2acc09fdb2d367799d765f7b34d490ba0d07ac21b957b1c73f7b5d554601",
            "48656c6c6f2c20776f726c6421",
            "89eb0d6a8a691dae2cd15ed0",
            "89eb0d6a8a691dae2cd15ed0369931ce0a949ecafa5c3f93f8121833646e15c3",
            "4164646974696f6e616c2064617461"
        };
    }
    
    public static IEnumerable<object[]> InvalidParameterSizes()
    {
        yield return new object[] { ModdedCTX.CommitmentSize + ModdedCTX.TagSize - 1, 0, ModdedCTX.NonceSize, ModdedCTX.KeySize, ModdedCTX.TagSize };
        yield return new object[] { ModdedCTX.CommitmentSize + ModdedCTX.TagSize, 1, ModdedCTX.NonceSize, ModdedCTX.KeySize, ModdedCTX.TagSize };
        yield return new object[] { ModdedCTX.CommitmentSize + ModdedCTX.TagSize, 0, ModdedCTX.NonceSize + 1, ModdedCTX.KeySize, ModdedCTX.TagSize };
        yield return new object[] { ModdedCTX.CommitmentSize + ModdedCTX.TagSize, 0, ModdedCTX.NonceSize - 1, ModdedCTX.KeySize, ModdedCTX.TagSize };
        yield return new object[] { ModdedCTX.CommitmentSize + ModdedCTX.TagSize, 0, ModdedCTX.NonceSize, ModdedCTX.KeySize + 1, ModdedCTX.TagSize };
        yield return new object[] { ModdedCTX.CommitmentSize + ModdedCTX.TagSize, 0, ModdedCTX.NonceSize, ModdedCTX.KeySize - 1, ModdedCTX.TagSize };
    }
    
    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Encrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> p = Convert.FromHexString(plaintext);
        Span<byte> c = stackalloc byte[p.Length + ModdedCTX.CommitmentSize + ModdedCTX.TagSize];
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> a = Convert.FromHexString(associatedData);
        
        ModdedCTX.Encrypt(c, p, n, k, a);
        
        Assert.AreEqual(ciphertext, Convert.ToHexString(c).ToLower());
    }
    
    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Encrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var a = new byte[associatedDataSize];
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ModdedCTX.Encrypt(c, p, n, k, a));
    }
    
    [TestMethod]
    [DynamicData(nameof(TestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Valid(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        Span<byte> c = Convert.FromHexString(ciphertext);
        Span<byte> p = stackalloc byte[c.Length - ModdedCTX.CommitmentSize - ModdedCTX.TagSize];
        Span<byte> n = Convert.FromHexString(nonce);
        Span<byte> k = Convert.FromHexString(key);
        Span<byte> a = Convert.FromHexString(associatedData);
        
        ModdedCTX.Decrypt(p, c, n, k, a);
        
        Assert.AreEqual(plaintext, Convert.ToHexString(p).ToLower());
    }
    
    [TestMethod]
    [DynamicData(nameof(TamperedTestVectors), DynamicDataSourceType.Method)]
    public void Decrypt_Tampered(string ciphertext, string plaintext, string nonce, string key, string associatedData)
    {
        var c = Convert.FromHexString(ciphertext);
        var p = new byte[c.Length - ModdedCTX.CommitmentSize - ModdedCTX.TagSize];
        var n = Convert.FromHexString(nonce);
        var k = Convert.FromHexString(key);
        var a = Convert.FromHexString(associatedData);
        
        Assert.ThrowsException<CryptographicException>(() => ModdedCTX.Decrypt(p, c, n, k, a));
    }
    
    [TestMethod]
    [DynamicData(nameof(InvalidParameterSizes), DynamicDataSourceType.Method)]
    public void Decrypt_Invalid(int ciphertextSize, int plaintextSize, int nonceSize, int keySize, int associatedDataSize)
    {
        var c = new byte[ciphertextSize];
        var p = new byte[plaintextSize];
        var n = new byte[nonceSize];
        var k = new byte[keySize];
        var a = new byte[associatedDataSize];
        
        Assert.ThrowsException<ArgumentOutOfRangeException>(() => ModdedCTX.Decrypt(p, c, n, k, a));
    }
}