<h1>reCAPTCHA library for .NET</h1>
reCAPTCHA for .NET is one of the most popular and well-documented reCAPTCHA libraries used by thousands of .NET developers in their ASP.NET web applications.
The library was created by <a href="http://twitter.com/tanveery">@tanveery</a> and has been forked from <a href="https://github.com/tanveery/recaptcha-net">https://github.com/tanveery/recaptcha-net</a>.
<h2>Highlights</h2>
<p>The following are the highlights of the library:</p>
<ul>
    <li>Renders reCAPTCHA widget and verifies reCAPTCHA response with minimal amount of code</li>
    <li>Provides reCAPTCHA web control (ASP.NET Web Forms for .NET Framework 4.5 and above)</li>
    <li>Provides HTML helper to quickly render reCAPTCHA widget (ASP.NET MVC 5)
    <li>Supports reCAPTCHA version 2</li>
    <li>Supports reCAPTCHA callback and reCAPTCHA expired callback</li>
</ul>
<h2>How to Use reCAPTCHA for .NET: Step-by-Step</h2>
<h3>Creating a reCAPTCHA API Key</h3>
<p>Before you can use reCAPTCHA in your web application, you must first create a reCAPTCHA API key (a pair of site and secret keys). Creating reCAPTCHA API key is very straight-forward. The following are the steps:</p>
<ol>
    <li>Go to the Google's <a href="https://www.google.com/recaptcha" target="_blank">reCAPTCHA</a> site.</li>
    <li>Click on the <strong>Admin Console</strong> menu option. You will be required to login with your Google account.</li>
    <li>In the <strong>Admin Console</strong> page, click on the <strong>Create</strong> button.</li>
    <li>Enter a label for your web application.</li>
    <li>Select <strong>reCAPTCHA v2</strong> option and then <strong>"I'm not a robot" Checkbox</strong> sub-option from the <strong>reCAPTCHA Type</strong> list.</li>
    <li>Enter the domain of your web application, e.g. example.com. If you are creating this key for your localhost, just enter localhost. You can enter more than one domain which is useful if you want the key to work across different hosts.</li>
    <li>Accept the reCAPTCHA terms of service.
    <li>Click on the <strong>Submit</strong> button.
    <li>Copy your <strong>Site Key</strong> and <strong>Secret Key</strong> which you would need to specify in your application's web.config file.</li>
</ol>
<h3>Installation</h3>
<p>The best and the recommended way to install the latest version of reCAPTCHA for .NET is through Nuget. From the <a href="http://docs.nuget.org/consume/package-manager-console">Nuget's Package Manager Console</a> in your Visual Studio .NET IDE, simply execute the following command:</p>
<pre><code>PM&gt; Install-Package RecaptchaNet</code></pre>
<p>You can also download a released build of reCAPTCHA for .NET by going to the <a href="https://github.com/RoadDirectLtd/recaptcha-dotnet4/releases">Releases</a> section of this project.
<h3>Set Configuration</h3>
<p><strong>ASP.NET Web Forms / ASP.NET MVC 5</strong></p>
<p>In the <strong>appSettings</strong> section of your <strong>web.config</strong> file, add the following keys:</p>
<pre><code>&lt;appSettings&gt;
&lt;add key="RecaptchaSiteKey" value="Your site key" /&gt;
&lt;add key="RecaptchaSecretKey" value="Your secret key" /&gt;
&lt;/appSettings&gt;
</code></pre>
<p><strong>ASP.NET</strong></p>
<p>In <strong>appsettings.json</strong>, add the following JSON properties:</p>
<pre><code>"RecaptchaSiteKey": "Your site key",
"RecaptchaSecretKey": "Your secret key"
</code></pre>
<p>In the <strong>ConfigureServices</strong> method of the <strong>Startup</strong> class, add the following line of code:</p>
<pre><code class="language-cs">using Recaptcha.Web.Configuration;
...
RecaptchaConfigurationManager.SetConfiguration(Configuration);</pre></code>
<h3>Render reCAPTCHA Widget</h3>
<p>You can either use the Recaptcha.Web.UI.Controls.RecaptchaWidget web control (ASP.NET Web Forms) or call the RecaptchaWidget method of HTML helper (ASP.NET MVC 5) to render reCAPTCHA widget:</p>
<p><strong>ASP.NET Web Forms</strong></p>
<pre><code>&lt;%@ Register Assembly="Recaptcha.Web" Namespace="Recaptcha.Web.UI.Controls" TagPrefix="cc1" %&gt;
...
&lt;cc1:RecaptchaWidget ID="Recaptcha1" runat="server" /&gt;
</code></pre>
<p><strong>ASP.NET MVC 5</strong></p>
<pre><code>@using Recaptcha.Web.Mvc;
...
@Html.RecaptchaWidget()
</code></pre>
<p>The above code by default renders both the API script as well as the widget. There are times when you want to render the API script and the widget separately such as the need to render multiple widgets on a page. The following is an example of how to achieve this:</p>
<p><strong>ASP.NET Web Forms</strong></p>
<pre><code>&lt;%@ Register Assembly="Recaptcha.Web" Namespace="Recaptcha.Web.UI.Controls" TagPrefix="cc1" %&gt;
...
&lt;cc1:RecaptchaApiScript ID="RecaptchaApiScript1" runat="server" /&gt;
&lt;cc1:RecaptchaWidget ID="RecaptchaWidget1" RenderApiScript="false" runat="server" /&gt;
&lt;cc1:RecaptchaWidget ID="RecaptchaWidget2" RenderApiScript="false" runat="server" /&gt;
</code></pre>
<p><strong>ASP.NET MVC 5</strong></p>
<pre><code>@using Recaptcha.Web.Mvc;
...
@Html.RecaptchaApiScript()
@Html.RecaptchaWidget(renderApiScript:false)
@Html.RecaptchaWidget(renderApiScript:false)
</code></pre>
<h3>Verify reCAPTCHA Response</h3>
<p>When your end-user submits the form that contains the reCAPTCHA widget, you can easily verify reCAPTCHA response with few lines of code:</p>
<p><strong>ASP.NET Web Form</strong></p>
<pre><code class="language-cs">if (String.IsNullOrEmpty(Recaptcha1.Response))
{
    lblMessage.Text = "Captcha cannot be empty.";
}
else
{
    var result = Recaptcha1.Verify();
    if (result.Success)
    {
        Response.Redirect("Welcome.aspx");
    }
    else
    {
        lblMessage.Text = "Error(s): ";
        foreach(var err in result.ErrorCodes)
        {
            lblMessage.Text = lblMessage.Text + err;
        }
    }
}
</code></pre>
<p><strong>ASP.NET MVC 5</strong></p>
<pre><code class="language-cs">using Recaptcha.Web.Mvc;
...
RecaptchaVerificationHelper recaptchaHelper = this.GetRecaptchaVerificationHelper();
if (String.IsNullOrEmpty(recaptchaHelper.Response))
{
    ModelState.AddModelError("", "Captcha answer cannot be empty.");
    return View(model);
}
RecaptchaVerificationResult recaptchaResult = recaptchaHelper.VerifyRecaptchaResponse();
if (recaptchaResult != RecaptchaVerificationResult.Success)
{
    ModelState.AddModelError("", "Incorrect captcha answer.");
}
</code></pre>
<h2>Attributes</h2>
<p>The attributes are used to control the behavior and appearance of the reCAPTCHA widget. They are specified in one of the three ways:</p>
<ul>
    <li>As API parameters (ASP.NET MVC helper methods)</li>
    <li>As properties of a web control (ASP.NET Web Control)</li>
    <li>Configuration (web.config / appsettings.json)
</ul>
<p>Assigning a value through method or property takes precedence over configuration. Of course, you don't need to set any attribute anywhere unless its required. The following is the entire list of the attributes:</p>
<table>
    <tr>
        <th>Attribute</th>
        <th>Description</th>
        <th>Type</th>
        <th>Values</th>
        <th>Default Value</th>
        <th>Configuration Key</th>
        <th>Required</th>
    </tr>
    <tr>
        <td><strong>Site Key</strong></td>
        <td>Site key for reCAPTCHA. It is required for rendering the widget.</td>
        <td><code>String</code></td>
        <td><em>The site key associated with the site you register in <a href="https://www.google.com/recaptcha/admin">Google reCAPTCHA Admin Console</a>.</em></td>
        <td><em>No default value. Must be provided.</em</td>
        <td><code>RecaptchaSiteKey</td>
        <td>Yes</td>
    </tr>
    <tr>
        <td><strong>Secret Key</strong></td>
        <td>Secret key for the reCAPTCHA. It is required for verifying reCAPTCHA response.</td>
        <td><code>String</code></td>
        <td><em>The secret key associated with the site you register in <a href="https://www.google.com/recaptcha/admin">Google reCAPTCHA Admin Console</a>.</em></td>
        <td><em>No default value. Must be provided.</em</td>
        <td><code>RecaptchaSecretKey</td>
        <td>Yes</td>
    </tr>
    <tr>
        <td><strong>APIVersion</strong></td>
        <td>Determines the version of the reCAPTCHA API.</td>
        <td><code>String</code></td>
        <td>-</td>
        <td>2</td>
        <td><code>RecaptchaApiVersion</td>
        <td>No</td>
    </tr>
    <tr>
        <td><strong>Language</strong></td>
        <td>Forces the reCAPTCHA widget to render in a specific language. By default, the user's language is used.</td>
        <td><code>String</code></td>
        <td><em>One of the values from the <a href="https://developers.google.com/recaptcha/docs/language">Language Codes</a> list.</em></td>
        <td><em>User's language</em></td>
        <td><code>RecaptchaLanguage</code></td>
        <td>No</td>
    </tr>
    <tr>
        <td><strong>Size</strong></td>
        <td>The size of the reCAPTCHA widget.</td>
        <td><code>RecaptchaSize</code> enum</td>
        <td><code>Default</code>, <code>Normal</code>, <code>Compact</code></td>
        <td><code>Default</code></td>
        <td><code>RecaptchaSize</code></td>
        <td>No</td>
    </tr>
    <tr>
        <td><strong>TabIndex</strong></td>
        <td>The tabindex of the reCAPTCHA widget.</td>
        <td><code>Int32</code></td>
        <td><em>Any integer</em></td>
        <td>0</td>
        <td>-</td>
        <td>No</td>
    </tr>
    <tr>
        <td><strong>Theme</strong></td>
        <td>The colour theme of the reCAPTCHA widget.</td>
        <td><code>RecaptchaTheme</code> enum</td>
        <td><code>Default</code>, <code>Light</code>, <code>Dark</code></td>
        <td><code>Default</code></td>
        <td><code>RecaptchaTheme</code></td>
        <td>No</td>
    </tr>
    <tr>
        <td><strong>Use SSL</strong></td>
        <td>Determines if SSL is to be used in Google reCAPTCHA API calls.</td>
        <td><code>RecaptchaSslBehavior</code> enum</td>
        <td><code>AlwaysUseSsl</code>, <code>SameAsRequestUrl</code>, <code>DoNotUseSsl</code></td>
        <td><code>AlwaysUseSsl</code></td>
        <td><code>RecaptchaUseSsl</code></td>
        <td>No</td>
    </tr>
    <tr>
        <td><strong>Callback</strong></td>
        <td>The name of your callback function, executed when the user submits a successful response. The g-recaptcha-response token is passed to your callback.</td>
        <td><code>String</code></td>
        <td><em>The name of a globally accessible function</em></td>
        <td><em>No default value.</em</td>
        <td><code>RecaptchaCallback</code></td>
        <td>No</td>
    </tr>
    <tr>
        <td><strong>Expired Callback</strong></td>
        <td>The name of your callback function, executed when the reCAPTCHA response expires and the user needs to re-verify.</td>
        <td><code>String</code></td>
        <td><em>The name of a globally accessible function</em></td>
        <td><em>No default value</em</td>
        <td><code>RecaptchaExpiredCallback</code></td>
        <td>No</td>
    </tr>
</table>