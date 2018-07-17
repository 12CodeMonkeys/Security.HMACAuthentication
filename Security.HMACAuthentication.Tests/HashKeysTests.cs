using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using Shouldly;

namespace Security.HMACAuthentication.Tests
{
    [TestClass]
    public class HashKeysTests
    {
        [TestMethod]
        public void Generating_new_keys_without_specifying_an_APPId_should_succeed()
        {
            // arrange
            var userId = "1";
            var hashAlgorithm = "MD5";
            var hmacAlgorithm = "HMACSHA256";

            // action
            var keys = HashKeys.GenerateHashKeys(userId, hashAlgorithm, hmacAlgorithm);

            // assert
            keys.APPId.ShouldNotBeNull();
            keys.APPId.ShouldNotBeEmpty();
        }

        [TestMethod]
        public void Generating_new_keys_by_specifying_an_APPId_should_succeed()
        {
            // arrange
            var userId = "2";
            var hashAlgorithm = "MD5";
            var hmacAlgorithm = "HMACSHA256";
            var appId = "my_fancy_new_apikey";

            // action
            var keys = HashKeys.GenerateHashKeys(userId, hashAlgorithm, hmacAlgorithm, appId);

            // assert
            keys.APPId.ShouldNotBeNull();
            keys.APPId.ShouldMatch(appId);
        }

        [TestMethod]
        public void Generating_new_keys_with_UserId_should_succeed()
        {
            // arrange
            var userId = "my_fany_user_id";
            var hashAlgorithm = "MD5";
            var hmacAlgorithm = "HMACSHA256";

            // action
            var keys = HashKeys.GenerateHashKeys(userId, hashAlgorithm, hmacAlgorithm);

            // assert
            keys.UserId.ShouldNotBeNull();
            keys.UserId.ShouldMatch(userId);
        }

        [TestMethod]
        public void Generating_HMACSHA_1_keys_should_succeed()
        {
            // arrange
            var userId = "";
            var hashAlgorithm = "MD5";
            var hmacAlgorithm = "HMACSHA1";

            // action
            var keys = HashKeys.GenerateHashKeys(userId, hashAlgorithm, hmacAlgorithm);

            // assert
            keys.ApiKey.ShouldNotBeNull();
            keys.ApiKey.ShouldNotBeEmpty();
            Convert.FromBase64String(keys.ApiKey).Length.ShouldBe(160 / 8);
        }

        [TestMethod]
        public void Generating_HMACSHA_256_keys_should_succeed()
        {
            // arrange
            var userId = "";
            var hashAlgorithm = "MD5";
            var hmacAlgorithm = "HMACSHA256";

            // action
            var keys = HashKeys.GenerateHashKeys(userId, hashAlgorithm, hmacAlgorithm);

            // assert
            keys.ApiKey.ShouldNotBeNull();
            keys.ApiKey.ShouldNotBeEmpty();
            Convert.FromBase64String(keys.ApiKey).Length.ShouldBe(256 / 8);
        }

        [TestMethod]
        public void Generating_HMACSHA_384_keys_should_succeed()
        {
            // arrange
            var userId = "";
            var hashAlgorithm = "MD5";
            var hmacAlgorithm = "HMACSHA384";

            // action
            var keys = HashKeys.GenerateHashKeys(userId, hashAlgorithm, hmacAlgorithm);

            // assert
            keys.ApiKey.ShouldNotBeNull();
            keys.ApiKey.ShouldNotBeEmpty();
            Convert.FromBase64String(keys.ApiKey).Length.ShouldBe(384 / 8);
        }

        [TestMethod]
        public void Generating_HMACSHA_512_keys_should_succeed()
        {
            // arrange
            var userId = "";
            var hashAlgorithm = "MD5";
            var hmacAlgorithm = "HMACSHA512";

            // action
            var keys = HashKeys.GenerateHashKeys(userId, hashAlgorithm, hmacAlgorithm);

            // assert
            keys.ApiKey.ShouldNotBeNull();
            keys.ApiKey.ShouldNotBeEmpty();
            Convert.FromBase64String(keys.ApiKey).Length.ShouldBe(512 / 8);
        }
    }
}