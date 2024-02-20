using System.Security.Cryptography;
using System.Text;

namespace password_hash_sha_256_salt_random.Services;

public class PasswordService
{
    private const int SaltSize = 32;

    private static byte[] GenerateSalt()
    {
        byte[] salt = new byte[SaltSize];

        using (RandomNumberGenerator randomSaltGeneretor = RandomNumberGenerator.Create())
        randomSaltGeneretor.GetBytes(salt);

        return salt;
    }

    public static string CreatePasswordHash(string password)
    {
        byte[] saltBytes = GenerateSalt();
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);
        
        byte[] hashBytes = CalculateHash(passwordBytes, saltBytes);

        return Convert.ToBase64String(hashBytes);
    }

    public static bool VerifyPassword(string password, string hashedPassword)
    {
        byte[] hashWithSalt = Convert.FromBase64String(hashedPassword);
        
        byte[] saltBytes = ExtractSalt(hashWithSalt);
        byte[] passwordBytes = Encoding.UTF8.GetBytes(password);

        byte[] computedHash = CalculateHash(passwordBytes, saltBytes);

        return CompareByteArrays(hashWithSalt, computedHash);
    }

    private static byte[] CalculateHash(byte[] passwordBytes, byte[] saltBytes)
    {
        byte[] combinedBytes = CombineByteArrays(passwordBytes, saltBytes);
        byte[] hashData = SHA256.HashData(combinedBytes);
        
        return CombineByteArrays(saltBytes, hashData);
    }

    private static bool CompareByteArrays(byte[] array1, byte[] array2)
    {
        if (array1.Length != array2.Length) return false;

        for (int i = 0; i < array1.Length; i++)
            if (array1[i] != array2[i]) return false;

        return true;
    }

    private static byte[] CombineByteArrays(byte[] array1, byte[] array2)
    {
        byte[] combined = new byte[array1.Length + array2.Length];
        
        Array.Copy(array1, 0, combined, 0, array1.Length);
        Array.Copy(array2, 0, combined, array1.Length, array2.Length);
        
        return combined;
    }

    private static byte[] ExtractSalt(byte[] hashWithSalt)
    {
        byte[] salt = new byte[SaltSize];

        Array.Copy(hashWithSalt, 0, salt, 0, SaltSize);

        return salt;
    }
}