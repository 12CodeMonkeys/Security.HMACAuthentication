using Microsoft.VisualStudio.TestTools.UnitTesting;
using Shouldly;
using System;
using System.Net.Http;
using System.Text;

namespace Security.HMACAuthentication.Tests
{
    [TestClass]
    public class SignerTests
    {
        [TestMethod]
        public void Computing_MD5_hash_should_succeed()
        {
            // arrange
            var plainText = "0123456789AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";
            var binary = Encoding.UTF8.GetBytes(plainText);

            // action
            var hash = Signer.ComputeHash("MD5", binary);
            var base64 = Convert.ToBase64String(hash);

            // assert
            base64.ShouldBe("yPg1cHFRX+J5WJEJ6JSVdw==");
        }

        [TestMethod]
        public void Computing_SHA1_hash_should_succeed()
        {
            // arrange
            var plainText = "0123456789AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";
            var binary = Encoding.UTF8.GetBytes(plainText);

            // action
            var hash = Signer.ComputeHash("SHA1", binary);
            var base64 = Convert.ToBase64String(hash);

            // assert
            base64.ShouldBe("1efIkENrz0GKJ9urTsnPeu/53Ec=");
        }

        [TestMethod]
        public void Computing_SHA256_hash_should_succeed()
        {
            // arrange
            var plainText = "0123456789AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";
            var binary = Encoding.UTF8.GetBytes(plainText);

            // action
            var hash = Signer.ComputeHash("SHA256", binary);
            var base64 = Convert.ToBase64String(hash);

            // assert
            base64.ShouldBe("q3BG713OEc/NIFAC/SsPoxWE1LZ6pJmeg4FaDi3PleU=");
        }

        [TestMethod]
        public void Computing_SHA384_hash_should_succeed()
        {
            // arrange
            var plainText = "0123456789AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";
            var binary = Encoding.UTF8.GetBytes(plainText);

            // action
            var hash = Signer.ComputeHash("SHA384", binary);
            var base64 = Convert.ToBase64String(hash);

            // assert
            base64.ShouldBe("dzQ106n+G+8sGvTABycMdfjL+0noDuEq3zBM+/mKHmIezIjuryr1/3oxb+Sr1Vsw");
        }

        [TestMethod]
        public void Computing_SHA512_hash_should_succeed()
        {
            // arrange
            var plainText = "0123456789AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";
            var binary = Encoding.UTF8.GetBytes(plainText);

            // action
            var hash = Signer.ComputeHash("SHA512", binary);
            var base64 = Convert.ToBase64String(hash);

            // assert
            base64.ShouldBe("dGUBug3iVy00uUcXgPx+NCtRnIz0riJNh0Th0m2Ie85qzh6OjIKfOd/t+JyEtsD5AXm/hxRgVFTw+qZApwFaRw==");
        }

        [TestMethod]
        public void Signing_with_null_message_body_should_succeed()
        {
            // arrange
            var signer = new Signer();
            var hashKeys = HashKeys.GenerateHashKeys("747D1358-89E4-4A49-BFB3-65E020D1D4BD", "MD5", "HMACSHA256", "MY_APPID");
            var authHeader = new AuthorizationHeader(hashKeys.APPId);
            var httpMethod = "GET";
            var requstUrl = @"https:\\LOCALHOST\MyApi\WonderLand";

            // action
            var signature = signer.Sign(requstUrl, httpMethod, null, authHeader, hashKeys);

            // assert
            signature.ShouldNotBeNull();
            signature.ShouldNotBeEmpty();
            signature.Length.ShouldBe(44);
        }

        [TestMethod]
        public void Signing_with_empty_message_body_should_succeed()
        {
            // arrange
            var signer = new Signer();
            var hashKeys = HashKeys.GenerateHashKeys("747D1358-89E4-4A49-BFB3-65E020D1D4BD", "MD5", "HMACSHA256", "MY_APPID");
            var authHeader = new AuthorizationHeader(hashKeys.APPId);
            var httpMethod = "GET";
            var requstUrl = @"https:\\LOCALHOST\MyApi\WonderLand";

            // action
            var signature = signer.Sign(requstUrl, httpMethod, new byte [0], authHeader, hashKeys);

            // assert
            signature.ShouldNotBeNull();
            signature.ShouldNotBeEmpty();
            signature.Length.ShouldBe(44);
        }

        [TestMethod]
        public void Signing_with_null_and_empty_message_body_should_generate_same_signatures()
        {
            // arrange
            var signer = new Signer();
            var hashKeys = HashKeys.GenerateHashKeys("747D1358-89E4-4A49-BFB3-65E020D1D4BD", "MD5", "HMACSHA256", "MY_APPID");
            var authHeader = new AuthorizationHeader(hashKeys.APPId);
            var httpMethod = "GET";
            var requstUrl = @"https:\\LOCALHOST\MyApi\WonderLand";

            // action
            var signature1 = signer.Sign(requstUrl, httpMethod, null, authHeader, hashKeys);
            var signature2 = signer.Sign(requstUrl, httpMethod, new byte [0], authHeader, hashKeys);

            // assert
            signature1.ShouldNotBeNull();
            signature1.ShouldNotBeEmpty();
            signature1.Length.ShouldBe(44);
            signature2.ShouldNotBeNull();
            signature2.ShouldNotBeEmpty();
            signature2.Length.ShouldBe(44);
            signature1.ShouldBe(signature2);
        }

        [TestMethod]
        public void Signing_with_same_url_with_different_casing_should_not_generate_same_signatures()
        {
            // arrange
            var signer = new Signer();
            var hashKeys = HashKeys.GenerateHashKeys("747D1358-89E4-4A49-BFB3-65E020D1D4BD", "MD5", "HMACSHA256", "MY_APPID");
            var authHeader = new AuthorizationHeader(hashKeys.APPId);
            var httpMethod = "GET";
            var requstUrl1 = @"HTTPS:\\localhost\MYAPI\WONDERLAND";
            var requstUrl2 = @"https:\\LOCALHOST\MyApi\wonderland";

            // action
            var signature1 = signer.Sign(requstUrl1, httpMethod, null, authHeader, hashKeys);
            var signature2 = signer.Sign(requstUrl2, httpMethod, null, authHeader, hashKeys);

            // assert
            signature1.ShouldNotBe(signature2);
        }

        [TestMethod]
        public void Signing_async_with_should_succeedAsync()
        {
            // arrange
            var signer = new Signer();
            var hashKeys = new HashKeys("ae5d53eb-e000-4de0-93a9-a70aa61300bf", "E0wMj/lLap3nmzOVYQUKdOlo/EuQRsFh76gxAaPRqZk=", "MD5", "HMACSHA256", "4735e15e-b85c-4010-b641-5736e9483b03");
            var authHeader = new AuthorizationHeader(hashKeys.APPId);
            var request = new HttpRequestMessage { Content = null, Method = HttpMethod.Get, RequestUri = new Uri("https://localhost:44321/HealthData/shared", UriKind.Absolute) };
       
            // action
            var signature = signer.SignAsync(request, authHeader, hashKeys).Result;

            // assert
            signature.ShouldNotBeNull();
            signature.ShouldNotBeEmpty();
            signature.Length.ShouldBe(44);
        }
    }
}
