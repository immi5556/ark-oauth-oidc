using System.Reflection;

namespace Ark.oAuth.Oidc.Code
{
    public class EmbeddedResourceUnpacker
    {
        /// <summary>
        /// Examines the Foundation DLL and creates files on disk for each of them
        /// </summary>
        /// <returns></returns>
        public async Task UnpackFiles(IWebHostEnvironment env)
        {
            // We only need to do this in Development mode.  The assumption being that the developer will have unpacked the correct Foundation
            // version and these files will be committed to source control etc, just like normal files
            if (!env.IsDevelopment()) return;

            var foundationAssembly = typeof(Ark.oAuth.Oidc.Code.EmbeddedResourceUnpacker).GetTypeInfo().Assembly;
            var assemblyName = foundationAssembly.GetName().Name;

            // Iterate over each embedded resource
            var names = foundationAssembly.GetManifestResourceNames();
            foreach (var name in names)
            {
                var filePath = name;

                // Embedded files are prefixed with the full namespace of the assembly, so your file is stored at wwwroot/foundation.css, then
                // Here, we strip the assembly name from the start - note the following '.' too
                filePath = filePath.Replace(assemblyName + ".", "");

                // Parse file path
                filePath = filePath.Replace(".", "\\");

                // Reset files - order is important!!
                filePath = this.ResetFileExtension(filePath, ".cshtml");
                filePath = this.ResetFileExtension(filePath, ".min.css");
                filePath = this.ResetFileExtension(filePath, ".css");
                filePath = this.ResetFileExtension(filePath, ".d.ts");
                filePath = this.ResetFileExtension(filePath, ".min.js");
                filePath = this.ResetFileExtension(filePath, ".js");
                filePath = this.ResetFileExtension(filePath, ".otf");
                filePath = this.ResetFileExtension(filePath, ".eot");
                filePath = this.ResetFileExtension(filePath, ".svg");
                filePath = this.ResetFileExtension(filePath, ".ttf");
                filePath = this.ResetFileExtension(filePath, ".woff");
                filePath = this.ResetFileExtension(filePath, ".png");
                filePath = this.ResetFileExtension(filePath, ".jpg");
                filePath = this.ResetFileExtension(filePath, ".gif");
                filePath = this.ResetFileExtension(filePath, ".ico");

                // Now prepend the root path of this application, on disk
                filePath = System.IO.Path.Combine(env.ContentRootPath, filePath);
                var directory = System.IO.Path.GetDirectoryName(filePath);
                System.IO.Directory.CreateDirectory(directory);
                // Copy
                using (var resource = Assembly.GetExecutingAssembly().GetManifestResourceStream(name))
                {
                    using (var file = new FileStream(filePath, FileMode.Create, FileAccess.ReadWrite))
                    {
                        resource.CopyTo(file);
                    }
                }
            }
        }

        /// <summary>
        /// Helper routine
        /// </summary>
        /// <param name="fileName"></param>
        /// <param name="requiredExtension"></param>
        /// <returns></returns>
        private string ResetFileExtension(string fileName, string requiredExtension)
        {
            var encodedExtension = requiredExtension.Replace(".", "\\");
            if (!fileName.EndsWith(encodedExtension)) return fileName;
            fileName = fileName.Substring(0, fileName.Length - encodedExtension.Length) + requiredExtension;
            return fileName;
        }
    }
    public static class ArkExtn
    {
        public static void AddArkAuth(this IServiceCollection services, IWebHostEnvironment environment)
        {
            var unpack = new EmbeddedResourceUnpacker();
            var task = unpack.UnpackFiles(environment);
            Task.WaitAll(task);
        }
    }
}
