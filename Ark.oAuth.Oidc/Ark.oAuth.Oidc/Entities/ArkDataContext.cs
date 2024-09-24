using Microsoft.EntityFrameworkCore;

namespace Ark.oAuth.Oidc
{
    public class ArkDataContext : DbContext
    {
        public virtual DbSet<ServiceAccount> service_accounts { get; set; }
        public virtual DbSet<User> users { get; set; }
        public virtual DbSet<UserRequest> user_request { get; set; }
        public virtual DbSet<ArkProject> oidc_project { get; set; }
        public virtual DbSet<PkceCodeFlow> pkce_code_flow { get; set; }
        public virtual DbSet<ArkClaim> oidc_claims { get; set; }
        public virtual DbSet<ArkScope> oidc_scopes { get; set; }
        public virtual DbSet<ClientRoleScope> client_role_scopes { get; set; }
        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<ArkProject>()
                .HasIndex(prop => prop.project_id);
            modelBuilder.Entity<ArkClaim>()
                .HasIndex(prop => prop.claim_id);
            modelBuilder.Entity<ArkScope>()
                .HasKey(prop => new { prop.scope_id, prop.claim_id });
            modelBuilder.Entity<ClientRoleScope>()
                .HasKey(prop => new { prop.client, prop.role });
            modelBuilder.Entity<User>()
                .HasIndex(prop => prop.email);
            modelBuilder.Entity<ServiceAccount>()
                .HasIndex(prop => prop.account_id);
        }
        public ArkDataContext(DbContextOptions<ArkDataContext> options) : base(options) { }
    }
}
