/* ============================================================================================================================
 * THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
 * LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 * =========================================================================================================================== */

using Newtonsoft.Json;
using Recaptcha.Web.Configuration;
using System;
using System.IO;
using System.Net;
using System.Threading.Tasks;
using System.Web;

namespace Recaptcha.Web
{
    /// <summary>
    /// Represents the functionality for verifying user's response to the recpatcha challenge.
    /// </summary>
    public class RecaptchaVerificationHelper
    {
        #region Constructors

        private RecaptchaVerificationHelper()
        { }

        /// <summary>
        /// Creates an instance of the <see cref="RecaptchaVerificationHelper"/> class.
        /// </summary>
        /// <param name="secretKey">Sets the secret key for the recaptcha verification request.</param>
        internal RecaptchaVerificationHelper(string secretKey)
        {
            if (string.IsNullOrEmpty(secretKey))
            {
                throw new InvalidOperationException("Secret key cannot be null or empty.");
            }

            if (HttpContext.Current == null || HttpContext.Current.Request == null)
            {
                throw new InvalidOperationException("Http request context does not exist.");
            }

            HttpRequest request = HttpContext.Current.Request;

            UseSsl = request.IsSecureConnection;

            SecretKey = secretKey;
            UserHostAddress = request.UserHostAddress;

            Response = request.Form["g-recaptcha-response"];
        }

        #endregion Constructors

        #region Properties

        /// <summary>
        /// Determines if HTTPS intead of HTTP is to be used in reCAPTCHA verification API calls.
        /// </summary>
        public bool UseSsl
        {
            get;
        }

        /// <summary>
        /// Gets the secret key for the recaptcha verification request.
        /// </summary>
        public string SecretKey
        {
            get;
        }

        /// <summary>
        /// Gets the user's host address for the reCAPTCHA verification request.
        /// </summary>
        public string UserHostAddress
        {
            get;
        }

        /// <summary>
        /// Gets the user's response to the recaptcha challenge of the recaptcha verification request.
        /// </summary>
        public string Response
        {
            get;
        }

        #endregion Properties

        #region Public Methods

        /// <summary>
        /// Verifies whether the user's response to the recaptcha request is correct.
        /// </summary>
        /// <returns>Returns the result as a value of the <see cref="RecaptchaVerificationResult"/> enum.</returns>
        public RecaptchaVerificationResult VerifyRecaptchaResponse()
        {
            if (string.IsNullOrEmpty(Response))
            {
                return new RecaptchaVerificationResult { Success = false };
            }

            string secretKey = SecretKey;

            if (string.IsNullOrEmpty(secretKey))
            {
                var config = RecaptchaConfigurationManager.GetConfiguration();
                secretKey = config.SecretKey;
            }

            return VerifyRecpatcha2Response(secretKey);
        }

        /// <summary>
        /// Verifies whether the user's response to the recaptcha request is correct.
        /// </summary>
        /// <returns>Returns the result as a value of the <see cref="RecaptchaVerificationResult"/> enum.</returns>
        public Task<RecaptchaVerificationResult> VerifyRecaptchaResponseTaskAsync()
        {
            if (string.IsNullOrEmpty(Response))
            {
                Task<RecaptchaVerificationResult>.Factory.StartNew(() => new RecaptchaVerificationResult { Success = false });
            }

            string secretKey = SecretKey;

            if (string.IsNullOrEmpty(secretKey))
            {
                var config = RecaptchaConfigurationManager.GetConfiguration();
                secretKey = config.SecretKey;
            }

            return VerifyRecpatcha2ResponseTaskAsync(secretKey);
        }

        #endregion Public Methods

        #region Private Methods

        private Task<RecaptchaVerificationResult> VerifyRecpatcha2ResponseTaskAsync(string secretKey)
        {
            Task<RecaptchaVerificationResult> taskResult = Task<RecaptchaVerificationResult>.Factory.StartNew(() =>
            {
                string postData = string.Format("secret={0}&response={1}&remoteip={2}", secretKey, Response, UserHostAddress);

                byte[] postDataBuffer = System.Text.Encoding.ASCII.GetBytes(postData);

                Uri verifyUri = new Uri($"https://{RecaptchaConfigurationManager.GetConfiguration().ApiSource}/api/siteverify", UriKind.Absolute);

                try
                {
                    var webRequest = (HttpWebRequest)WebRequest.Create(verifyUri);
                    webRequest.ContentType = "application/x-www-form-urlencoded";
                    webRequest.ContentLength = postDataBuffer.Length;
                    webRequest.Method = "POST";

                    var proxy = WebRequest.GetSystemWebProxy();
                    proxy.Credentials = CredentialCache.DefaultCredentials;

                    webRequest.Proxy = proxy;

                    using (var requestStream = webRequest.GetRequestStream())
                    {
                        requestStream.Write(postDataBuffer, 0, postDataBuffer.Length);
                    }

                    var webResponse = (HttpWebResponse)webRequest.GetResponse();

                    string sResponse = null;

                    using (var sr = new StreamReader(webResponse.GetResponseStream()))
                    {
                        sResponse = sr.ReadToEnd();
                    }

                    return JsonConvert.DeserializeObject<RecaptchaVerificationResult>(sResponse);
                }
                catch (Exception ex)
                {
                    throw ex;
                }
            });

            return taskResult;
        }

        private RecaptchaVerificationResult VerifyRecpatcha2Response(string secretKey)
        {
            string postData = string.Format("secret={0}&response={1}&remoteip={2}", secretKey, Response, UserHostAddress);

            byte[] postDataBuffer = System.Text.Encoding.ASCII.GetBytes(postData);
            Uri verifyUri = new Uri($"https://{RecaptchaConfigurationManager.GetConfiguration().ApiSource}/api/siteverify", UriKind.Absolute);
            try
            {
                var webRequest = (HttpWebRequest)WebRequest.Create(verifyUri);
                webRequest.ContentType = "application/x-www-form-urlencoded";
                webRequest.ContentLength = postDataBuffer.Length;
                webRequest.Method = "POST";

                var proxy = WebRequest.GetSystemWebProxy();
                proxy.Credentials = CredentialCache.DefaultCredentials;

                webRequest.Proxy = proxy;

                using (var requestStream = webRequest.GetRequestStream())
                {
                    requestStream.Write(postDataBuffer, 0, postDataBuffer.Length);
                }

                var webResponse = (HttpWebResponse)webRequest.GetResponse();

                string sResponse = null;

                using (var sr = new StreamReader(webResponse.GetResponseStream()))
                {
                    sResponse = sr.ReadToEnd();
                }

                return JsonConvert.DeserializeObject<RecaptchaVerificationResult>(sResponse);
            }
            catch (Exception ex)
            {
                throw ex;
            }
        }

        #endregion Private Methods
    }
}
