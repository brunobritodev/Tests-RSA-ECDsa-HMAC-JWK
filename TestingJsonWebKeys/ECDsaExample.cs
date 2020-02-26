using System;
using System.Collections.Generic;
using System.IO;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace TestingJsonWebKeys
{
    public class ECDsaExample
    {
        private static DateTime Now = DateTime.Now;
        private static SecurityTokenDescriptor Jwt = new SecurityTokenDescriptor
        {
            Issuer = "www.mysite.com",
            Audience = "your-spa",
            IssuedAt = Now,
            NotBefore = Now,
            Expires = Now.AddHours(1),
            Subject = new ClaimsIdentity(new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Email, "meuemail@gmail.com", ClaimValueTypes.Email),
                new Claim(JwtRegisteredClaimNames.GivenName, "Bruno Brito"),
                new Claim(JwtRegisteredClaimNames.Sub, Guid.NewGuid().ToString())
            })
        };
        private static TokenValidationParameters TokenValidationParams = new TokenValidationParameters
        {
            ValidIssuer = "www.mysite.com",
            ValidAudience = "your-spa",
        };


        public static void Run()
        {
            var tokenHandler = new JsonWebTokenHandler();
            var key = new ECDsaSecurityKey(ECDsa.Create(ECCurve.NamedCurves.nistP256))
            {
                KeyId = Guid.NewGuid().ToString()
            };

            Jwt.SigningCredentials = new SigningCredentials(key, SecurityAlgorithms.EcdsaSha256);
            var lastJws = tokenHandler.CreateToken(Jwt);
            Console.WriteLine($"{lastJws}{Environment.NewLine}");


            // Store in filesystem
            // Store HMAC os Filesystem, recover and test if it's valid
            var parameters = key.ECDsa.ExportParameters(true);
            var jwk = new JsonWebKey()
            {
                Kty = JsonWebAlgorithmsKeyTypes.EllipticCurve,
                Use = "sig",
                Kid = key.KeyId,
                KeyId = key.KeyId,
                X = Base64UrlEncoder.Encode(parameters.Q.X),
                Y = Base64UrlEncoder.Encode(parameters.Q.Y),
                D = Base64UrlEncoder.Encode(parameters.D),
                Crv = JsonWebKeyECTypes.P256,
                Alg = "ES256"
            };

            File.WriteAllText("current-ecdsa.key", JsonConvert.SerializeObject(jwk));

            var storedJwk = JsonConvert.DeserializeObject<JsonWebKey>(File.ReadAllText("current-ecdsa.key"));
            TokenValidationParams.IssuerSigningKey = storedJwk;
            var validationResult = tokenHandler.ValidateToken(lastJws, TokenValidationParams);

            Console.WriteLine(validationResult.IsValid);
        }
    }
}