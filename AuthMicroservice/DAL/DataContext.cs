using AuthMicroservice.DAL.Entities;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthMicroservice.DAL;

public class DataContext : IdentityDbContext<User>
{
    public DataContext(DbContextOptions options) : base(options)
    {
    }
}
