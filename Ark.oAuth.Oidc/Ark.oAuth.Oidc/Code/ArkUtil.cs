using System.Text.Json.Nodes;

namespace Ark.oAuth
{
    public class ArkUtil
    {
        //https://rsa-key-gen.immanuel.co/api/keys
        public static async Task<dynamic> GetKeys()
        {
            HttpClient httpClient = new HttpClient();
            httpClient.BaseAddress = new Uri(@"https://rsa-key-gen.immanuel.co");
            var resp = await httpClient.GetStringAsync("api/keys");
            var jo = System.Text.Json.JsonSerializer.Deserialize<JsonObject>(resp);
            return new
            {
                private_key = jo["private_key"]?.GetValue<string>(),
                public_key = jo["public_key"]?.GetValue<string>()
            };
        }
    }
}
