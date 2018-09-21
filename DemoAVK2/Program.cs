using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Configuration.AzureKeyVault;
using Microsoft.Extensions.Logging;

namespace DemoAVK2
{
    public class Program
    {
        private static string GetKeyVaultEndpoint() => "https://amethystevault.vault.azure.net";

        public static void Main(string[] args)
        {
            CreateWebHostBuilder(args).Build().Run();
        }

        public static IWebHostBuilder CreateWebHostBuilder(string[] args) =>
            WebHost.CreateDefaultBuilder(args)
                .ConfigureAppConfiguration((ctx, builder) =>
                {
                    string keyVaultEndpoint = GetKeyVaultEndpoint();

                    if (!string.IsNullOrEmpty(keyVaultEndpoint))
                    {
                        AzureServiceTokenProvider azureServiceTokenProvider = 
                                new AzureServiceTokenProvider();

                        KeyVaultClient keyVaultClient = new KeyVaultClient(
                            new KeyVaultClient.AuthenticationCallback(
                                azureServiceTokenProvider.KeyVaultTokenCallback));

                        builder.AddAzureKeyVault(
                            keyVaultEndpoint, keyVaultClient, 
                            new DefaultKeyVaultSecretManager());
                    }
                }
        ).UseStartup<Startup>();
    }
}

//Microsoft.Extensions.Configuration.AzureKeyVault
