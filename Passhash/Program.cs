﻿using Microsoft.AspNetCore.Cryptography.KeyDerivation;
using System;
using System.Security.Cryptography;


namespace Passhash
{
    class Program
    {
        static void Main(string[] args)
        {
            //user input
            Console.Write("Enter a password: ");
            string password = Console.ReadLine();

            //--------------------SALT-------------------------------
            // salt is random data that is used as an additional
            //input to a one - way function that "hashes" data,

           
            // generate a 128-bit salt using a secure PRNG
            byte[] salt = new byte[128 / 8];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(salt);
            }

            Console.WriteLine($"Salt: {Convert.ToBase64String(salt)}");
            //--------------------------------------------------------


            // derive a 256-bit subkey (use HMACSHA1 with 10,000 iterations)
            string hashed = Convert.ToBase64String(KeyDerivation.Pbkdf2(
                
                password: password,
                salt: salt,

                prf: KeyDerivationPrf.HMACSHA1,
                iterationCount: 10000,
                numBytesRequested: 256 / 8)
                
                );


            Console.WriteLine($"Hashed: {hashed}");


        }
    }
}
