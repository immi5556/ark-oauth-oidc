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
        protected override void OnConfiguring(DbContextOptionsBuilder options)
        => options.UseSqlite($"Data Source=./data/ntt_auth.db");
        //protected override void OnConfiguring(DbContextOptionsBuilder options)
        //    => options.UseMySQL($"Server=ntt-cad-mysql-d.mysql.database.azure.com; port=3306;UID=cad_db_adm;Pwd=Asdf!234;Database=ntt_cad_auth_d;SslMode=Required;SslCa=C:\\Immi\\NTT\\Pres-AI\\Azure\\DigiCertGlobalRootG2.crt.pem");

        public ArkDataContext(DbContextOptions<ArkDataContext> options) : base(options) { }
    }
}
