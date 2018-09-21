using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using DemoAVK.Models;
using Microsoft.Azure.Services.AppAuthentication;
using Microsoft.Azure.KeyVault;
using Microsoft.Azure.KeyVault.Models;
using Microsoft.Extensions.Configuration;

namespace DemoAVK.Controllers
{
    public class HomeController : Controller
    {
 

        public async Task<IActionResult> Index()
        {
            AzureServiceTokenProvider azureServiceTokenProvider = 
                new AzureServiceTokenProvider();

            using (KeyVaultClient keyVaultClient =
                new KeyVaultClient(
                new KeyVaultClient.AuthenticationCallback(azureServiceTokenProvider.KeyVaultTokenCallback)
                ))
            {
                string identifier = "https://amethystevault.vault.azure.net/secrets/password";
                SecretBundle secret = await keyVaultClient.GetSecretAsync(identifier);

                ViewBag.Secret = secret.Value;
            }
            return View();
        }
        
    }
}
