#pragma checksum "D:\fido-Eric\uaf-frontend-enrollment\Rancher\UAF_Frontend_Registration\Views\Home\Login.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "ac3713e30707ce505d4d1afdb7b2e04a0b5398c6"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Home_Login), @"mvc.1.0.view", @"/Views/Home/Login.cshtml")]
namespace AspNetCore
{
    #line hidden
    using System;
    using System.Collections.Generic;
    using System.Linq;
    using System.Threading.Tasks;
    using Microsoft.AspNetCore.Mvc;
    using Microsoft.AspNetCore.Mvc.Rendering;
    using Microsoft.AspNetCore.Mvc.ViewFeatures;
#nullable restore
#line 1 "D:\fido-Eric\uaf-frontend-enrollment\Rancher\UAF_Frontend_Registration\Views\_ViewImports.cshtml"
using UAF_Frontend_Registration;

#line default
#line hidden
#nullable disable
#nullable restore
#line 2 "D:\fido-Eric\uaf-frontend-enrollment\Rancher\UAF_Frontend_Registration\Views\_ViewImports.cshtml"
using UAF_Frontend_Registration.Models;

#line default
#line hidden
#nullable disable
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"ac3713e30707ce505d4d1afdb7b2e04a0b5398c6", @"/Views/Home/Login.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"8f3e1f2a03f9d8ed69a18a4679bdcb447fdcd13a", @"/Views/_ViewImports.cshtml")]
    public class Views_Home_Login : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<UAF_Frontend_Registration.Models.User>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            WriteLiteral("\r\n\r\n");
#nullable restore
#line 4 "D:\fido-Eric\uaf-frontend-enrollment\Rancher\UAF_Frontend_Registration\Views\Home\Login.cshtml"
  
    ViewBag.Title = "Login";
    Layout = "~/Views/Shared/_Layout.cshtml";

#line default
#line hidden
#nullable disable
            WriteLiteral(@"
<div class=""text-center"">
    <h3 class=""display-4"">Welcome to Fido Registration</h3>
</div>
<br />

<div class=""row justify-content-md-center"">

    <div class=""col-md-8"">
        <div class=""card"">
            <div class=""card-header"">
                Please Login by Your Staff Account
            </div>
            <div class=""card-body"">
");
#nullable restore
#line 22 "D:\fido-Eric\uaf-frontend-enrollment\Rancher\UAF_Frontend_Registration\Views\Home\Login.cshtml"
                 using (Html.BeginForm("Login", "Home", FormMethod.Post))
                {

#line default
#line hidden
#nullable disable
            WriteLiteral("                <div class=\"form-group\">\r\n                    ");
#nullable restore
#line 25 "D:\fido-Eric\uaf-frontend-enrollment\Rancher\UAF_Frontend_Registration\Views\Home\Login.cshtml"
               Write(Html.LabelFor(m => m.Email));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n                    ");
#nullable restore
#line 26 "D:\fido-Eric\uaf-frontend-enrollment\Rancher\UAF_Frontend_Registration\Views\Home\Login.cshtml"
               Write(Html.TextBoxFor(m => m.Email, "", new { @class = "form-control", @placeholder = "xxxx@email.com", required = "required", type = "email" }));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n                </div>\r\n                <div class=\"form-group\">\r\n                    ");
#nullable restore
#line 29 "D:\fido-Eric\uaf-frontend-enrollment\Rancher\UAF_Frontend_Registration\Views\Home\Login.cshtml"
               Write(Html.LabelFor(m => m.Password));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n                    ");
#nullable restore
#line 30 "D:\fido-Eric\uaf-frontend-enrollment\Rancher\UAF_Frontend_Registration\Views\Home\Login.cshtml"
               Write(Html.PasswordFor(m => m.Password, new { @class = "form-control", @placeholder = "Password", required = "required" }));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n                </div>\r\n                <div class=\"form-group\">\r\n                    ");
#nullable restore
#line 33 "D:\fido-Eric\uaf-frontend-enrollment\Rancher\UAF_Frontend_Registration\Views\Home\Login.cshtml"
               Write(Html.LabelFor(m => m.Activation_Code));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n                    ");
#nullable restore
#line 34 "D:\fido-Eric\uaf-frontend-enrollment\Rancher\UAF_Frontend_Registration\Views\Home\Login.cshtml"
               Write(Html.PasswordFor(m => m.Activation_Code, new { @class = "form-control", @placeholder = "Please fill an activation code from your email.", required = "required" }));

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n                </div>\r\n                <div class=\"form-group\">\r\n                    <input type=\"submit\" name=\"submit\" class=\"btn btn-primary\" value=\"Login\" />\r\n                </div>\r\n");
#nullable restore
#line 39 "D:\fido-Eric\uaf-frontend-enrollment\Rancher\UAF_Frontend_Registration\Views\Home\Login.cshtml"

                    if (!string.IsNullOrEmpty(@Model.login_status))
                    {

#line default
#line hidden
#nullable disable
            WriteLiteral("                <div class=\"alert alert-danger d-flex align-items-center\" id=\"loginAlert\">\r\n                    ");
#nullable restore
#line 43 "D:\fido-Eric\uaf-frontend-enrollment\Rancher\UAF_Frontend_Registration\Views\Home\Login.cshtml"
               Write(Model.login_status);

#line default
#line hidden
#nullable disable
            WriteLiteral(@"
                </div>
                <script type=""text/javascript"">
                    setTimeout(function () {

                        // Closing the alert
                        $('#loginAlert').alert('close');
                    }, 5000);
                </script>
");
#nullable restore
#line 52 "D:\fido-Eric\uaf-frontend-enrollment\Rancher\UAF_Frontend_Registration\Views\Home\Login.cshtml"
                    }
                }

#line default
#line hidden
#nullable disable
            WriteLiteral("            </div>\r\n        </div>\r\n    </div>\r\n</div>\r\n");
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<UAF_Frontend_Registration.Models.User> Html { get; private set; }
    }
}
#pragma warning restore 1591