using Microsoft.EntityFrameworkCore;

namespace Ark.oAuth.Oidc
{
    public class ArkDataContext : DbContext
    {
        public virtual DbSet<ArkServiceAccount> service_accounts { get; set; }
        public virtual DbSet<ArkUser> users { get; set; }
        public virtual DbSet<PkceCodeFlow> pkce_code_flow { get; set; }
        public virtual DbSet<ArkClaim> oidc_claims { get; set; }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<ArkClaim>()
                .HasIndex(prop => prop.key);
            modelBuilder.Entity<ArkUser>()
                .HasIndex(prop => prop.user_id);
            modelBuilder.Entity<ArkServiceAccount>()
                .HasIndex(prop => prop.account_id);
        }

        public ArkDataContext(DbContextOptions<ArkDataContext> options) : base(options) { }
    }
}
