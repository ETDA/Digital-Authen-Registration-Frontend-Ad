using IdentityServerHost.Quickstart.UI;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using Novell.Directory.Ldap;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Claims;
using UAF_Frontend_Registration.Models;
using UAF_Frontend_Registration.Services;
using UAF_Frontend_Registration.Settings;

namespace UAF_Frontend_Registration.Controllers
{
    [SecurityHeaders]
    public class HomeController : Controller
    {
        private readonly ILoggerFactory _loggerFactory;
        private readonly ICallbackSettings _callbackurl;
        private readonly ILDAPSettings _ldapConfig;

        public HomeController(ILoggerFactory loggerFactory, ICallbackSettings callbackurl, ILDAPSettings ldapConfig)
        {
            this._callbackurl = callbackurl;
            this._ldapConfig = ldapConfig;

            loggerFactory =
              LoggerFactory.Create(builder =>
                  builder.AddSimpleConsole(options =>
                  {
                      options.IncludeScopes = true;
                      options.SingleLine = true;
                      options.TimestampFormat = "[yyyy-MM-dd HH:mm:ss]: ";
                  }));
            this._loggerFactory = loggerFactory;
        }

        public IActionResult Index()
        {
            if (HttpContext.Request.Cookies.ContainsKey("FidoLoginCookie"))
            {
                return RedirectToAction("Login");
            }
            else
            {
                return RedirectToAction("Register");
            }
        }

        [Authorize]
        public IActionResult Privacy()
        {
            return View();
        }

        [Authorize]
        public ActionResult Register()
        {
            return View();
        }

        [Authorize]
        public ActionResult PleaseWait()
        {

            if (!string.IsNullOrEmpty(HttpContext.Session.GetString("User")))
            {
                var _logger = _loggerFactory.CreateLogger<HomeController>();

                try
                {
                    _logger.LogInformation("Fido Registration Success");
                    return RedirectToAction("Success");

                }
                catch (Exception ex)
                {
                    ex.StackTrace.ToString();
                    return RedirectToAction("Error");
                }
            }
            else
            {
                return RedirectToAction("Error");
            }
        }

        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        public ActionResult Login()
        {
            if (HttpContext.Request.Cookies.ContainsKey("FidoLoginCookie"))
            {
                return RedirectToAction("Register");
            }
            else
            {
                return View(new User { login_status = null });
            }
        }

        [HttpPost]
        [Authorize]
        public ActionResult Register(string email)
        {

            var _logger = _loggerFactory.CreateLogger<HomeController>();
            try
            {
                _logger.LogInformation("-----Start Fodo Registration-----");
                _logger.LogInformation("Username: " + email);

                var name = email.Split("@")[0];
                _logger.LogInformation("Name: " + name);

                var qrcode_resp = requestQrCode(email, name, _logger);

                if (qrcode_resp == null)
                {
                    return View("Error");
                }
                else
                {
                    _logger.LogInformation("Get Qr Code Success");
                    return View("QRCode", qrcode_resp);
                }
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                ex.StackTrace.ToString();
                return View("Error");
            }
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Login(string email, string password, string activation_code)
        {
            if (ModelState.IsValid)
            {
                var _logger = _loggerFactory.CreateLogger<HomeController>();
                LdapConnection connection = new LdapConnection();
                ActivateCodeResponse resp = new ActivateCodeResponse();
                try
                {
                    _logger.LogInformation("-----Start Login-----");
                    _logger.LogInformation("Username: " + email);
                    _logger.LogInformation("Activation Code: " + activation_code);

                    connection.Connect(_ldapConfig.AD_domain, _ldapConfig.AD_port);
                    connection.Bind(email, password);

                    var userClaims = new List<Claim>() { new Claim(ClaimTypes.NameIdentifier, email), };

                    var claimsIdentity = new ClaimsIdentity(userClaims, CookieAuthenticationDefaults.AuthenticationScheme);
                    var authProperties = new AuthenticationProperties
                    {
                        ExpiresUtc = DateTime.Now.AddMinutes(30),
                    };
                    var userPrincipal = new ClaimsPrincipal(new[] { claimsIdentity });

                    HttpContext.SignInAsync(userPrincipal, authProperties);
                    HttpContext.Session.SetString("User", email);

                    _logger.LogInformation("Login Success");
                }
                catch (Exception ex)
                {

                    HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    HttpContext.Session.Remove("User");
                    HttpContext.Response.Cookies.Delete(".AspNetCore.Session");

                    var status = ex.Message.ToString();

                    if (status == "Connect Error")
                    {
                        _logger.LogError("Connection to LDAP Error");
                        return View(new User { login_status = "Can not Login ! - Please check your vpn or internet connection" });
                    }
                    else if (status == "Invalid Credentials")
                    {
                        _logger.LogError("Username Password Invalid");
                        return View(new User { login_status = "Username OR Password Invalid !" });
                    }
                    else if (status == "Activation Code Invalid")
                    {
                        _logger.LogError("Activation Code Invalid");
                        return View(new User { login_status = "Activation Code Invalid! Please contact Admin" });
                    }
                    else if (status == resp.description)
                    {
                        _logger.LogError(resp.description);
                        return View(new User { login_status = resp.description });
                    }
                    else
                    {
                        _logger.LogError("Unknown Error: " + status);
                        return View(new User { login_status = "Apologize - The system is under maintenance. Please try again later" });
                    }
                }
                finally
                {
                    connection.Disconnect();
                }
            }
            return RedirectToAction("Register", "Home");
        }

        [HttpGet]
        [Authorize]
        public ActionResult Logout()
        {
            var _logger = _loggerFactory.CreateLogger<HomeController>();

            HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            HttpContext.Response.Cookies.Delete(".AspNetCore.Session");
            HttpContext.Session.Remove("User");

            _logger.LogInformation("Logout Success");

            return RedirectToAction("Login", new { ReturnUrl = "/Home/Register" });
        }

        [HttpGet]
        [Authorize]
        public ActionResult Discard()
        {
            return RedirectToAction("Register");
        }

        [Authorize]
        public ActionResult Success()
        {
            var _logger = _loggerFactory.CreateLogger<HomeController>();

            HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
            HttpContext.Response.Cookies.Delete(".AspNetCore.Session");
            HttpContext.Session.Remove("User");

            _logger.LogInformation("Logout Success");


            return View();
        }

        [Authorize]
        public ActionResult QRCodeError()
        {
            return View();
        }

        private QRCodeResp requestQrCode(string identity, string name, ILogger<HomeController> _logger)
        {
            try
            {

                _logger.LogInformation("----- Start Request QR Code -----");
                QRCodeRequestService qr_req = new QRCodeRequestService(_loggerFactory);
                return qr_req.qrCodeAsync(identity, name, _callbackurl.Register_request, _callbackurl.Qrcode_request, _callbackurl.Credentials);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex.Message);
                ex.StackTrace.ToString();
                return null;
            }
        }
    }
}