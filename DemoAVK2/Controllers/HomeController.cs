using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using DemoAVK2.Models;
using Microsoft.Extensions.Configuration;

namespace DemoAVK2.Controllers
{
    public class HomeController : Controller
    {
        private readonly IConfiguration _configuration = null;

        public HomeController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public IActionResult Index()
        {
            ViewBag.Secret = _configuration["password"];
            return View();
        }

    }
}
