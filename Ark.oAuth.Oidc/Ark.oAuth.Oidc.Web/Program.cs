using Ark.oAuth;
using Ark.oAuth.Oidc;

var builder = WebApplication.CreateBuilder(args);

// The identity provider itself.
builder.Services.AddArkOidcServer(builder.Environment);

// The IdP's own admin console signs in through the IdP, so it is also a client.
builder.Services.AddArkOidcClient(builder.Configuration);

builder.Services.AddControllersWithViews();

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}

app.UsePathBase("/auth");
app.UseHttpsRedirection();
app.UseStaticFiles();

// Middleware order matters here.
//
// UseRouting has to run before UseAuthentication/UseAuthorization: without a selected endpoint,
// the authorization middleware cannot see the [Authorize] metadata it is meant to enforce.
// (This ran in the opposite order previously.)
app.UseRouting();
app.UseArkOidcCors();   // token/userinfo/discovery for the origins in Oidc:CorsOrigins
app.UseArkAuthData();   // one-time database bootstrap
app.UseArkOidcClient(); // no-op unless ark_oauth_client:UseLegacyFlow is set
app.UseAuthentication();
app.UseAuthorization();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
