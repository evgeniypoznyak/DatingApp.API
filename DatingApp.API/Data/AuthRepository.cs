using System;
using System.Threading.Tasks;
using DatingApp.API.Models;
using Microsoft.EntityFrameworkCore;

namespace DatingApp.API.Data
{
    class AuthRepository : IAuthRepository
    {
        private readonly DataContext _context;

        public AuthRepository(DataContext context)
        {
            _context = context;
        }

        public async Task<User> Login(string username, string password)
        {
            var user = await _context.Users.FirstOrDefaultAsync(x => x.UserName == username);

            if (user == null) return null; // if return null, controller return 401 Unauthorized

            // if return null, controller return 401 Unauthorized
            if (!VerifyPasswordHash(password, user.PasswordHash, user.PasswordSalt)) return null;

            return user;
        }

        private bool VerifyPasswordHash(string password, byte[] userPasswordHash, byte[] userPasswordSalt)
        {
            using var hmac = new System.Security.Cryptography.HMACSHA512(userPasswordSalt);
            var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            
            // simplified LINQ version:
            // return !computedHash.Where((t, i) => t != userPasswordHash[i]).Any();
            for (var i = 0; i < computedHash.Length; i++)
            {
                if (computedHash[i] != userPasswordHash[i])
                {
                    return false;
                }
            }

            return true;
        }

        public async Task<User> Register(User user, string password)
        {
            var (salt, hash) = GenerateSaltHashTuple(password);
            user.PasswordSalt = salt;
            user.PasswordHash = hash;
            await _context.Users.AddAsync(user);
            await _context.SaveChangesAsync();
            return user;
        }

        private Tuple<byte[], byte[]> GenerateSaltHashTuple(string password)
        {
            using var hmac = new System.Security.Cryptography.HMACSHA512();
            return new Tuple<byte[], byte[]>(
                hmac.Key, // salt
                hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password)) // hash
            );
        }


        public async Task<bool> UserExist(string username)
        {
            return await _context.Users.AnyAsync(x => x.UserName == username);
        }
    }
}