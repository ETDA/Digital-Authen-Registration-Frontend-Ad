#pragma checksum "D:\fido-Eric\uaf-frontend-enrollment\Rancher\UAF_Frontend_Registration\Views\Home\Success.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "afd357857aff353082ac2da62cc696e4adb537a2"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Home_Success), @"mvc.1.0.view", @"/Views/Home/Success.cshtml")]
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
#nullable restore
#line 3 "D:\fido-Eric\uaf-frontend-enrollment\Rancher\UAF_Frontend_Registration\Views\Home\Success.cshtml"
using Microsoft.AspNetCore.Http;

#line default
#line hidden
#nullable disable
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"afd357857aff353082ac2da62cc696e4adb537a2", @"/Views/Home/Success.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"8f3e1f2a03f9d8ed69a18a4679bdcb447fdcd13a", @"/Views/_ViewImports.cshtml")]
    public class Views_Home_Success : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<UAF_Frontend_Registration.Models.User>
    {
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            WriteLiteral("\r\n");
            WriteLiteral("\r\n");
#nullable restore
#line 5 "D:\fido-Eric\uaf-frontend-enrollment\Rancher\UAF_Frontend_Registration\Views\Home\Success.cshtml"
  
    ViewData["Title"] = "Register Success";
    Layout = "~/Views/Shared/_Layout.cshtml";

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n\r\n<div class=\"text-center\">\r\n    <h1 class=\"display-4\">Registration Success!</h1>\r\n</div>\r\n\r\n<br />\r\n<br />\r\n\r\n");
#nullable restore
#line 18 "D:\fido-Eric\uaf-frontend-enrollment\Rancher\UAF_Frontend_Registration\Views\Home\Success.cshtml"
 using (Html.BeginForm("Register", "Home", FormMethod.Get))
{


#line default
#line hidden
#nullable disable
            WriteLiteral("    <div class=\"text-center\">\r\n        <div class=\"d-grid gap-2 col-6 mx-auto\">\r\n            <input type=\"submit\" name=\"submit\" class=\"btn btn-success\" value=\"Back to Home\" />\r\n        </div>\r\n    </div>\r\n");
#nullable restore
#line 26 "D:\fido-Eric\uaf-frontend-enrollment\Rancher\UAF_Frontend_Registration\Views\Home\Success.cshtml"

}

#line default
#line hidden
#nullable disable
            WriteLiteral("\r\n");
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
