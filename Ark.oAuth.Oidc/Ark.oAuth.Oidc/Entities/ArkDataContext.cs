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
        //protected override void OnConfiguring(DbContextOptionsBuilder options)
        //=> options.UseSqlite($"Data Source=./data/ntt_auth.db");
        //protected override void OnConfiguring(DbContextOptionsBuilder options)
        //=> options.UseMySQL($"Server=\"ntt-cad-mysql-d.mysql.database.azure.com\"; port=\"3306\" UserID = \"cad_db_adm\";Password=\"{{your_password}}\";Database=\"{{your_database}}\";SslMode=Required;SslCa=\"{{path_to_CA_cert}}\"");
        protected override void OnConfiguring(DbContextOptionsBuilder options)
        => options.UseMySQL($"Server=ntt-cad-mysql-d.mysql.database.azure.com; port=3306;UID=cad_db_adm;Pwd=Asdf!234;Database=ntt_cad_auth_d;SslMode=Required;SslCa=C:\\Immi\\NTT\\Pres-AI\\Azure\\DigiCertGlobalRootG2.crt.pem");

        public ArkDataContext(DbContextOptions<ArkDataContext> options) : base(options) { }
    }
}
