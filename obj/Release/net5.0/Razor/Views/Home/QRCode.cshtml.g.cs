#pragma checksum "D:\User\Downloads\uaffront-uat\uaffront-uat\Views\Home\QRCode.cshtml" "{ff1816ec-aa5e-4d10-87f7-6f4963833460}" "4b59681b3a0ecdcbb7576f76e5ea191f68e116a8"
// <auto-generated/>
#pragma warning disable 1591
[assembly: global::Microsoft.AspNetCore.Razor.Hosting.RazorCompiledItemAttribute(typeof(AspNetCore.Views_Home_QRCode), @"mvc.1.0.view", @"/Views/Home/QRCode.cshtml")]
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
#line 1 "D:\User\Downloads\uaffront-uat\uaffront-uat\Views\_ViewImports.cshtml"
using UAF_Frontend_Registration;

#line default
#line hidden
#nullable disable
#nullable restore
#line 2 "D:\User\Downloads\uaffront-uat\uaffront-uat\Views\_ViewImports.cshtml"
using UAF_Frontend_Registration.Models;

#line default
#line hidden
#nullable disable
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"4b59681b3a0ecdcbb7576f76e5ea191f68e116a8", @"/Views/Home/QRCode.cshtml")]
    [global::Microsoft.AspNetCore.Razor.Hosting.RazorSourceChecksumAttribute(@"SHA1", @"558b3c17b7a4714f671279842d532d7009029dc7", @"/Views/_ViewImports.cshtml")]
    public class Views_Home_QRCode : global::Microsoft.AspNetCore.Mvc.Razor.RazorPage<UAF_Frontend_Registration.Models.QRCodeResp>
    {
        private static readonly global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute __tagHelperAttribute_0 = new global::Microsoft.AspNetCore.Razor.TagHelpers.TagHelperAttribute("name", "_Nav", global::Microsoft.AspNetCore.Razor.TagHelpers.HtmlAttributeValueStyle.DoubleQuotes);
        #line hidden
        #pragma warning disable 0649
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperExecutionContext __tagHelperExecutionContext;
        #pragma warning restore 0649
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperRunner __tagHelperRunner = new global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperRunner();
        #pragma warning disable 0169
        private string __tagHelperStringValueBuffer;
        #pragma warning restore 0169
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager __backed__tagHelperScopeManager = null;
        private global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager __tagHelperScopeManager
        {
            get
            {
                if (__backed__tagHelperScopeManager == null)
                {
                    __backed__tagHelperScopeManager = new global::Microsoft.AspNetCore.Razor.Runtime.TagHelpers.TagHelperScopeManager(StartTagHelperWritingScope, EndTagHelperWritingScope);
                }
                return __backed__tagHelperScopeManager;
            }
        }
        private global::Microsoft.AspNetCore.Mvc.TagHelpers.PartialTagHelper __Microsoft_AspNetCore_Mvc_TagHelpers_PartialTagHelper;
        #pragma warning disable 1998
        public async override global::System.Threading.Tasks.Task ExecuteAsync()
        {
            WriteLiteral("\n");
            WriteLiteral("\n\n");
#nullable restore
#line 6 "D:\User\Downloads\uaffront-uat\uaffront-uat\Views\Home\QRCode.cshtml"
  
    ViewData["Title"] = "Scan Qr Code";
    Layout = "~/Views/Shared/_Layout.cshtml";

#line default
#line hidden
#nullable disable
            WriteLiteral("\n");
            __tagHelperExecutionContext = __tagHelperScopeManager.Begin("partial", global::Microsoft.AspNetCore.Razor.TagHelpers.TagMode.SelfClosing, "4b59681b3a0ecdcbb7576f76e5ea191f68e116a83701", async() => {
            }
            );
            __Microsoft_AspNetCore_Mvc_TagHelpers_PartialTagHelper = CreateTagHelper<global::Microsoft.AspNetCore.Mvc.TagHelpers.PartialTagHelper>();
            __tagHelperExecutionContext.Add(__Microsoft_AspNetCore_Mvc_TagHelpers_PartialTagHelper);
            __Microsoft_AspNetCore_Mvc_TagHelpers_PartialTagHelper.Name = (string)__tagHelperAttribute_0.Value;
            __tagHelperExecutionContext.AddTagHelperAttribute(__tagHelperAttribute_0);
            await __tagHelperRunner.RunAsync(__tagHelperExecutionContext);
            if (!__tagHelperExecutionContext.Output.IsContentModified)
            {
                await __tagHelperExecutionContext.SetOutputContentAsync();
            }
            Write(__tagHelperExecutionContext.Output);
            __tagHelperExecutionContext = __tagHelperScopeManager.End();
            WriteLiteral("\n\n<style>\n    img {\n        display: block;\n        margin-left: auto;\n        margin-right: auto;\n    }\n</style>\n\n<br />\n<br />\n\n<div class=\"text-center\">\n    <h1 class=\"display-4\">Please Scan QR Code</h1>\n</div>\n\n<br />\n<br />\n\n");
#nullable restore
#line 31 "D:\User\Downloads\uaffront-uat\uaffront-uat\Views\Home\QRCode.cshtml"
 using (Html.BeginForm("Register", "Home", FormMethod.Get))
{

#line default
#line hidden
#nullable disable
            WriteLiteral("    <div class=\"text-center\">\n        <img");
            BeginWriteAttribute("src", " src=", 581, "", 599, 1);
#nullable restore
#line 34 "D:\User\Downloads\uaffront-uat\uaffront-uat\Views\Home\QRCode.cshtml"
WriteAttributeValue("", 586, Model.qrcode, 586, 13, false);

#line default
#line hidden
#nullable disable
            EndWriteAttribute();
            WriteLiteral(@" style=""width:20%"" />
        <br />
        <div>
            <span>QR Code is valid for </span><span id=""sec""></span><span> seconds</span>
        </div>
        <br />
        <input type=""submit"" name=""submit"" class=""btn btn-discard"" value=""Discard"" />
    </div>
");
            WriteLiteral("    <script type=\"text/javascript\">\n        let qrToken = \"");
#nullable restore
#line 44 "D:\User\Downloads\uaffront-uat\uaffront-uat\Views\Home\QRCode.cshtml"
                  Write(Model.qrToken);

#line default
#line hidden
#nullable disable
            WriteLiteral("\";\n\n        let url = \"");
#nullable restore
#line 46 "D:\User\Downloads\uaffront-uat\uaffront-uat\Views\Home\QRCode.cshtml"
              Write(CallbackSettings.Token_request);

#line default
#line hidden
#nullable disable
            WriteLiteral(@""";
        let t = setInterval(function () {
            let token = parseJwt(qrToken);
            fetch(url + qrToken)
                .then((e) => e.json())
                .then(function (e) {
                    if (!e.success) {
                        window.location = '");
#nullable restore
#line 53 "D:\User\Downloads\uaffront-uat\uaffront-uat\Views\Home\QRCode.cshtml"
                                      Write(Url.Action("QRCodeError", "Home"));

#line default
#line hidden
#nullable disable
            WriteLiteral("\';\n\n                    }\n\n                    if (e.data.status === \"used\") {\n                        window.location = \'");
#nullable restore
#line 58 "D:\User\Downloads\uaffront-uat\uaffront-uat\Views\Home\QRCode.cshtml"
                                      Write(Url.Action("PleaseWait", "Home"));

#line default
#line hidden
#nullable disable
            WriteLiteral(@"';
                    }

                })

                $(""#sec"").text(Math.floor(((token.exp) - (new Date() / 1000))+2));
    }, 1000)

    function parseJwt(token) {
        var base64Url = token.split('.')[1];
        var base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        var jsonPayload = decodeURIComponent(atob(base64).split('').map(function (c) {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));

        return JSON.parse(jsonPayload);
    };
    </script>
");
#nullable restore
#line 76 "D:\User\Downloads\uaffront-uat\uaffront-uat\Views\Home\QRCode.cshtml"


}

#line default
#line hidden
#nullable disable
            WriteLiteral("\n");
        }
        #pragma warning restore 1998
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public UAF_Frontend_Registration.Settings.ICallbackSettings CallbackSettings { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.ViewFeatures.IModelExpressionProvider ModelExpressionProvider { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IUrlHelper Url { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.IViewComponentHelper Component { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IJsonHelper Json { get; private set; }
        [global::Microsoft.AspNetCore.Mvc.Razor.Internal.RazorInjectAttribute]
        public global::Microsoft.AspNetCore.Mvc.Rendering.IHtmlHelper<UAF_Frontend_Registration.Models.QRCodeResp> Html { get; private set; }
    }
}
#pragma warning restore 1591
