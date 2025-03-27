using JWTAuthDotNet9.Entities;
using Microsoft.EntityFrameworkCore;

namespace JWTAuthDotNet9.Data
{
    public class UserDbContext(DbContextOptions<UserDbContext> options) : DbContext(options)
    {
        public /* virtual*/ DbSet<User> Users { get; set; }
    }
}
