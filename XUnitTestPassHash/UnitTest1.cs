using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System;
using System.Security.Cryptography;
using Xunit;

namespace XUnitTestPassHash
{
    public class UnitTest1
    {

        [Fact]
        public void PassTest1()
        {
          var expected =  MakeHash("12345");
          var actual =  MakeHash("12345");

            Assert.Equal(expected, actual);
        }


        [Fact]
        public void FailTest1()
        {
            var expected = MakeHash("1234");
            var actual = MakeHash("12345");

            Assert.Equal(expected, actual);

        }



        public string MakeHash(string password)
        {
            // generate a 128-bit salt using a secure PRNG
            byte[] salt = new byte[128 / 8];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            };
         
            // derive a 256-bit subkey (use HMACSHA1 with 10,000 iterations)
            string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(

                password: password,
                salt: salt,

                prf: KeyDerivationPrf.HMACSHA1,
                iterationCount: 10000,
                numBytesRequested: 256 / 8));

            return hashed;
        }
    }
}
